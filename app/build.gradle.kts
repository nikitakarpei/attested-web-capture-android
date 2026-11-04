import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlinx.kover") // test coverage
}

android {
    namespace = "io.github.nikitakarpei.attestedwebcapture"
    compileSdk = 37
    buildToolsVersion = "37.0.0" // pinned for reproducibility

    defaultConfig {
        applicationId = "io.github.nikitakarpei.attestedwebcapture"
        minSdk = 28
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
    }

    // The tests run against the release build: a debuggable build never creates a key. AGP only makes unit tests
    // for the tested build type.
    testBuildType = "release"

    buildTypes {
        release {
            isMinifyEnabled = false
            isDebuggable = false
            // Unsigned: the key never enters the build. CI's release job or tools/sign.sh signs.
            // Without this, the git commit is embedded and source archives build differently from checkouts.
            vcsInfo.include = false
        }
    }

    // Otherwise AGP adds a dependency list encrypted for Google Play, different on every build.
    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }

    // Uncompressed: compressed bytes differ between JDK builds' zlib, which would break reproducibility.
    androidResources {
        noCompress += ""
    }

    packaging {
        resources.pickFirsts += listOf("META-INF/LICENSE.md", "META-INF/LICENSE.txt", "META-INF/LICENSE")
        resources.excludes += listOf("META-INF/versions/*/OSGI-INF/MANIFEST.MF", "META-INF/versions/*/module-info.class")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    lint {
        warningsAsErrors = true
        abortOnError = true
        checkReleaseBuilds = true
        checkTestSources = true
        // Results depend on the day (new versions published), not the code; unchanged commits would start failing.
        disable += listOf("GradleDependency", "NewerVersionAvailable", "AndroidGradlePluginVersion", "OldTargetApi")
    }

    testOptions {
        unitTests.all {
            it.systemProperty("e2e.dir", rootProject.file("build/e2e").absolutePath)
            it.systemProperty("tools.dir", rootProject.file("tools").absolutePath)
            it.inputs.dir(rootProject.file("tools")) // the tests run the fake attestation from there
            // ...with the first python3 on PATH, by its absolute path ("" if there is none: then only the tests fail).
            val path = System.getenv("PATH").orEmpty().split(File.pathSeparator)
            val python = path.map { dir -> File(dir, "python3") }.firstOrNull { file -> file.canExecute() }
            it.systemProperty("python", python?.absolutePath.orEmpty())
            it.systemProperty("fuzz.seeds", file("src/test/fuzz/request").absolutePath)
            it.testLogging { showStandardStreams = true }
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
        allWarningsAsErrors.set(true)
    }
}

// Library startup profiles are zlib-compressed too (see androidResources), and a proxy gains nothing from them.
tasks.matching { it.name.contains("ArtProfile") }.configureEach { enabled = false }

// Tools, not part of the app; pinned in gradle/verification-metadata.xml like everything else.
val ktlint = configurations.create("ktlint")
val jazzer = configurations.create("jazzer")

dependencies {
    ktlint("com.pinterest.ktlint:ktlint-cli:1.8.0") {
        attributes { attribute(Bundling.BUNDLING_ATTRIBUTE, objects.named(Bundling.EXTERNAL)) }
    }
    jazzer("com.code-intelligence:jazzer:0.30.0")
}

val kotlinSources = listOf("src/**/*.kt", "*.kts", "../*.kts")

tasks.register<JavaExec>("ktlintCheck") {
    description = "Checks the Kotlin code style (.editorconfig)."
    group = "verification"
    classpath = ktlint
    mainClass.set("com.pinterest.ktlint.Main")
    args = kotlinSources
}

tasks.register<JavaExec>("ktlintFormat") {
    description = "Fixes Kotlin code style findings where ktlint can."
    group = "formatting"
    classpath = ktlint
    mainClass.set("com.pinterest.ktlint.Main")
    jvmArgs("--add-opens=java.base/java.lang=ALL-UNNAMED")
    args = listOf("-F") + kotlinSources
}

// -PfuzzSeconds=N (default 60). A crash fails the task and leaves the input in build/fuzz/.
tasks.register<JavaExec>("fuzzRequest") {
    description = "Fuzzes the proxy's request parser with Jazzer."
    group = "verification"
    val test = tasks.named<Test>("testReleaseUnitTest")
    dependsOn("compileReleaseUnitTestKotlin")
    classpath = jazzer + files(test.map { it.classpath })
    mainClass.set("com.code_intelligence.jazzer.Jazzer")
    jvmArgs("-XX:+EnableDynamicAgentLoading", "-Xmx1g")
    val out = layout.buildDirectory.dir("fuzz")
    val seconds = providers.gradleProperty("fuzzSeconds").orElse("60")
    doFirst { out.get().dir("corpus").asFile.mkdirs() }
    argumentProviders.add(
        CommandLineArgumentProvider {
            listOf(
                "--target_class=io.github.nikitakarpei.attestedwebcapture.RequestFuzzer",
                "--instrumentation_includes=io.github.nikitakarpei.attestedwebcapture.**:okhttp3.**",
                "--keep_going=0",
                "-max_total_time=${seconds.get()}",
                "-max_len=20000",
                "-dict=${file("src/test/fuzz/request.dict")}",
                "-artifact_prefix=${out.get().asFile}/",
                out.get().dir("corpus").asFile.path,
                file("src/test/fuzz/request").path,
            )
        },
    )
}

kover {
    reports {
        variant("release") {
            // The screen and the service only run on a phone (with them, coverage is ~61%).
            filters {
                excludes {
                    classes(
                        "io.github.nikitakarpei.attestedwebcapture.CaptureService*",
                        "io.github.nikitakarpei.attestedwebcapture.MainActivity*",
                    )
                }
            }
            verify { rule { minBound(80) } }
        }
    }
}

dependencies {
    implementation("com.squareup.okhttp3:okhttp:5.5.1")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.86")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20260814") // Android has it built in
}

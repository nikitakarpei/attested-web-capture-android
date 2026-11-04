pluginManagement {
    repositories {
        google()
        maven("https://repo1.maven.org/maven2")
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        maven("https://repo1.maven.org/maven2")
        mavenCentral()
    }
}
rootProject.name = "attested-web-capture"
include(":app")

// Build tools that still use vulnerable versions of these libraries are given the fixed ones; none of the
// libraries is in the app. Each rule only raises a version: remove it once the tool ships the fix itself.
val fixedVersions = mapOf(
    "ch.qos.logback:logback-classic" to "1.5.34", // ktlint
    "ch.qos.logback:logback-core" to "1.5.34",
    "com.google.guava:guava" to "33.7.2-jre", // AGP and its lint
    "org.apache.commons:commons-lang3" to "3.18.0",
    "org.apache.httpcomponents:httpclient" to "4.5.13",
    "org.bitbucket.b_c:jose4j" to "0.9.6",
    "org.bouncycastle:bcpkix-jdk18on" to "1.86", // the app's version
    "org.bouncycastle:bcprov-jdk18on" to "1.86",
    "org.bouncycastle:bcutil-jdk18on" to "1.86",
    "org.freemarker:freemarker" to "2.3.35", // Kover's report generator
    "org.jdom:jdom2" to "2.0.6.1",
)

fun isOlder(version: String, than: String): Boolean {
    val a = version.split('.', '-').map { it.toIntOrNull() ?: 0 }
    val b = than.split('.', '-').map { it.toIntOrNull() ?: 0 }
    for (i in 0 until maxOf(a.size, b.size)) {
        val (x, y) = a.getOrElse(i) { 0 } to b.getOrElse(i) { 0 }
        if (x != y) return x < y
    }
    return false
}

fun Configuration.useFixedVersions() = resolutionStrategy.eachDependency {
    val fixed = fixedVersions["${requested.group}:${requested.name}"]
    val version = requested.version
    if (fixed != null && version != null && isOlder(version, fixed)) {
        useVersion(fixed)
        because("fixes known vulnerabilities")
    }
}

gradle.beforeProject {
    buildscript.configurations.configureEach { useFixedVersions() }
    configurations.configureEach { useFixedVersions() }
}

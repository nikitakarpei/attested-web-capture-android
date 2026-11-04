plugins {
    id("com.android.application") version "9.5.0" apply false
    // AGP compiles Kotlin itself (built-in Kotlin); this only chooses the Kotlin version it uses.
    id("org.jetbrains.kotlin.android") version "2.4.21" apply false
    id("org.jetbrains.kotlinx.kover") version "0.9.11" apply false
}

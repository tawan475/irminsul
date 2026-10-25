plugins {
    id("com.android.application")
}

val ndkVersionName = "30.0.16248370"

android {
    namespace = "io.github.tawan475.irminsul"
    compileSdk = 36
    ndkVersion = ndkVersionName

    defaultConfig {
        applicationId = "io.github.tawan475.irminsul"
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "0.0.0-spike"
        ndk { abiFilters += listOf("arm64-v8a") }
    }

    sourceSets {
        getByName("main") {
            jniLibs.directories.add(layout.buildDirectory.dir("rustJniLibs").get().asFile.path)
        }
    }
}

// The native forwarder (android/native) built by cargo-ndk into the jniLibs
// folder above. The repo's rust-toolchain.toml picks the toolchain.
val sdkDir = androidComponents.sdkComponents.sdkDirectory
val cargoNdk = tasks.register<Exec>("cargoNdk") {
    val out = layout.buildDirectory.dir("rustJniLibs").get().asFile
    workingDir = rootProject.file("native")
    doFirst { environment("ANDROID_NDK_HOME", sdkDir.get().asFile.resolve("ndk/$ndkVersionName").path) }
    commandLine("cargo", "ndk", "-t", "arm64-v8a", "-P", "29", "-o", out.path, "build", "--release")
}

tasks.named("preBuild") { dependsOn(cargoNdk) }

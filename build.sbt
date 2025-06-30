import play.sbt.PlayImport.PlayKeys.{playInteractionMode, playMonitoredFiles}
import play.sbt.PlayInteractionMode
import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.{FileSystems, Files, Paths}
import sbt.complete.Parsers.spaceDelimited
import scala.collection.JavaConverters._
import scala.sys.process.Process
import scala.sys.process._
import sbt.Tests.{SubProcess, Group}

// ------------------------------------------------------------------------------------------------
// Functions
// ------------------------------------------------------------------------------------------------

def log(msg: String): Unit = {
  println(s"[sbt log] $msg")
}

// ------------------------------------------------------------------------------------------------
// Task Keys
// ------------------------------------------------------------------------------------------------

lazy val runBackend = taskKey[Unit]("Run Backend")
lazy val versionGenerate = taskKey[Int]("Add version_metadata.json file")
lazy val installFrontendDependencies =
  taskKey[Unit]("Install frontend dependencies via npm")

lazy val frontendBuild =
  taskKey[Unit]("Build production version of frontend code.")
val cleanFrontend = taskKey[Int]("Clean frontend")

lazy val frontendTests = taskKey[Unit]("Run UI tests when testing application.")

lazy val releaseModulesLocally = taskKey[Int]("Release modules locally")
lazy val downloadThirdPartyDeps =
  taskKey[Int]("Downloading thirdparty dependencies")

lazy val devSpaceReload = taskKey[Int]("DevSpace reload")

// ------------------------------------------------------------------------------------------------
// Main build.sbt script
// ------------------------------------------------------------------------------------------------

name := """Authlete-Java-Play-3""".stripMargin

version := "1.0-SNAPSHOT"

// javacOptions ++= Seq("-source", "17", "-target", "17")
// Prevents websockets from being closed by the server
//PlayKeys.devSettings += "play.server.websocket.periodic-keep-alive-mode" -> "pong"
ThisBuild / publish / skip := true

ThisBuild / Test / javaOptions ++= Seq(
  "-Dconfig.resource=application.test.conf"
)
// This is for dev-mode server. In dev-mode, the play server is started before the files are compiled.
// Hence, the application files are not available in the path. For prod, It is in reference.conf file.
PlayKeys.devSettings += "play.pekko.dev-mode.pekko.coordinated-shutdown.phases.service-requests-done.timeout" -> "150s"

// add the classpath to be managed
//Compile / managedClasspath += baseDirectory.value / "target/scala-2.13/"

version := sys.process.Process("cat version.txt").lineStream_!.head

Global / onChangedBuildSource := IgnoreSourceChanges

val pac4jVersion = "6.1.3"
val saml = "org.pac4j" % "pac4j-saml" % pac4jVersion exclude (
  "commons-io",
  "commons-io"
) exclude ("org.opensaml", "opensaml-core-api")
val pac4jDependencies = Seq(
  "org.pac4j" % "pac4j-ldap" % pac4jVersion,
  "org.pac4j" % "pac4j-core" % pac4jVersion,
  "org.pac4j" % "pac4j-oidc" % pac4jVersion,
  "org.pac4j" % "pac4j-jwt" % pac4jVersion,
  "org.pac4j" % "pac4j-http" % pac4jVersion,
  "org.pac4j" % "pac4j-cas" % pac4jVersion,
  "org.pac4j" % "pac4j-oauth" % pac4jVersion,
  saml
).map(
  _ excludeAll (
    ExclusionRule("commons-io", "commons-io"),
    ExclusionRule(organization = "com.fasterxml.jackson.core")
  )
)

lazy val root = (project in file("."))
  .enablePlugins(PlayJava)
  .enablePlugins(UniversalPlugin, DockerPlugin, GraalVMNativeImagePlugin)
  .settings(
    libraryDependencies ++= Seq(
      guice,
      ws,
      jdbc,
      evolutions,
      logback,
      ehcache,
      filters,
      openId,
      pac4jDependencies,
      "org.apache.commons" % "commons-lang3" % "3.17.0",
      "com.nimbusds" % "nimbus-jose-jwt" % "10.3",
      "com.nimbusds" % "oauth2-oidc-sdk" % "11.26",
      "com.github.pureconfig" %% "pureconfig-core" % "0.17.9",
      "com.github.pureconfig" %% "pureconfig-generic-scala3" % "0.17.9",
      // "io.github.iltotore" %% "iron-pureconfig" % "3.0.0"
      "org.playframework" %% "play-mailer" % "10.1.0",
      "org.playframework" %% "play-mailer-guice" % "10.1.0",
      "org.pac4j" %% "play-pac4j" % "12.0.2-PLAY3.0",
      "com.sendgrid" % "sendgrid-java" % "4.10.3",
      "de.dentrassi.crypto" % "pem-keystore" % "3.0.0",
      "com.microsoft.azure" % "msal4j" % "1.21.0",
      "com.azure" % "azure-core" % "1.55.3",
      "com.azure" % "azure-identity" % "1.16.1",
      "com.azure" % "azure-security-keyvault-keys" % "4.9.4",
      "com.azure" % "azure-storage-blob" % "12.30.0",
      "com.azure" % "azure-storage-blob-batch" % "12.26.0",
      "com.azure.resourcemanager" % "azure-resourcemanager" % "2.51.0",
      "com.azure.resourcemanager" % "azure-resourcemanager-marketplaceordering" % "1.0.0",
      "com.authlete" % "authlete-java-common" % "4.20",
      "ch.qos.logback" % "logback-classic" % "1.5.18",
      "jakarta.mail" % "jakarta.mail-api" % "2.1.2",
      "io.swagger.core.v3" % "swagger-annotations" % "2.2.31",
      "com.bettercloud" % "vault-java-driver" % "5.1.0",
      "org.bouncycastle" % "bc-fips" % "2.1.0",
      "org.bouncycastle" % "bcpkix-fips" % "2.1.9",
      "org.bouncycastle" % "bctls-fips" % "2.1.20",
      "com.zaxxer" % "HikariCP" % "6.3.0",
      "com.google.cloud" % "google-cloud-secretmanager" % "2.66.0",
      "com.google.apis" % "google-api-services-compute" % "v1-rev20250415-2.0.0",
      "com.google.apis" % "google-api-services-iam" % "v2-rev20250502-2.0.0",
      "com.google.cloud" % "google-cloud-compute" % "1.73.0",
      "com.google.cloud" % "google-cloud-storage" % "2.52.3",
      "com.google.cloud" % "google-cloud-kms" % "2.66.0",
      "com.google.cloud" % "google-cloud-resourcemanager" % "1.65.0",
      "com.google.cloud" % "google-cloud-logging" % "3.22.4",
      "com.google.oauth-client" % "google-oauth-client" % "1.39.0",
      "org.projectlombok" % "lombok" % "1.18.38",
      "com.amazonaws" % "aws-java-sdk-ec2" % "1.12.785",
      "com.amazonaws" % "aws-java-sdk-kms" % "1.12.785",
      "com.amazonaws" % "aws-java-sdk-iam" % "1.12.785",
      "com.amazonaws" % "aws-java-sdk-sts" % "1.12.785",
      "com.amazonaws" % "aws-java-sdk-s3" % "1.12.785",
      "com.amazonaws" % "aws-java-sdk-elasticloadbalancingv2" % "1.12.785",
      "com.amazonaws" % "aws-java-sdk-route53" % "1.12.785",
      "com.amazonaws" % "aws-java-sdk-cloudtrail" % "1.12.785",
      "software.amazon.awssdk" % "rds" % "2.31.70",
      "jakarta.validation" % "jakarta.validation-api" % "3.1.1",
      "jakarta.persistence" % "jakarta.persistence-api" % "3.2.0",
      "org.postgresql" % "postgresql" % "42.7.7",
      "org.flywaydb" % "flyway-core" % "11.9.1",
      "io.ebean" % "ebean" % "17.0.0-RC3",
      "be.objectify" %% "deadbolt-java" % "3.0.0" // not part of  Pac4j Implementation For Play Framework (Scala 3) in vers
    )
  )
  .settings(
    libraryDependencies ++= Seq(
      "org.scalatestplus.play" %% "scalatestplus-play" % "7.0.1" % Test,
      "qa.hedgehog" %% "hedgehog-sbt" % "0.12.0" % Test,
      // https://hedgehog.qa/
      "qa.hedgehog" %% "hedgehog-core" % "0.12.0" % Test
    )
  )
// .in(file("."))
// .enablePlugins(PlayJava)
  .disablePlugins(PlayLayoutPlugin)

ThisBuild / scalaVersion := "3.3.6"

routesGenerator := InjectedRoutesGenerator
generateReverseRouter := false

generateJsReverseRouter := false

val pekkoVersion = "1.1.4"

val pekkoLibs = Seq(
  "org.apache.pekko" %% "pekko-actor-typed",
  "org.apache.pekko" %% "pekko-actor",
  "org.apache.pekko" %% "pekko-protobuf-v3",
  "org.apache.pekko" %% "pekko-serialization-jackson",
  "org.apache.pekko" %% "pekko-slf4j",
  "org.apache.pekko" %% "pekko-stream"
)

val pekkoOverrides = pekkoLibs.map(_ % pekkoVersion)

dependencyOverrides ++= pekkoOverrides

val jacksonVersion = "2.19.1"

val jacksonLibs = Seq(
  "com.fasterxml.jackson.core" % "jackson-core",
  "com.fasterxml.jackson.core" % "jackson-annotations",
  "com.fasterxml.jackson.core" % "jackson-databind",
  "com.fasterxml.jackson.datatype" % "jackson-datatype-jdk8",
  "com.fasterxml.jackson.datatype" % "jackson-datatype-jsr310",
  "com.fasterxml.jackson.dataformat" % "jackson-dataformat-cbor",
  "com.fasterxml.jackson.dataformat" % "jackson-dataformat-xml",
  "com.fasterxml.jackson.dataformat" % "jackson-dataformat-yaml",
  "com.fasterxml.jackson.module" % "jackson-module-parameter-names",
  "com.fasterxml.jackson.module" %% "jackson-module-scala"
)

val jacksonOverrides = jacksonLibs.map(_ % jacksonVersion)

dependencyOverrides ++= jacksonOverrides

val samlOverrides = Seq(
  // "org.opensaml" % "opensaml-core-api",
  "org.opensaml" % "opensaml-saml-api",
  "org.opensaml" % "opensaml-saml-impl",
  "org.opensaml" % "opensaml-soap-api",
  "org.opensaml" % "opensaml-xmlsec-api",
  "org.opensaml" % "opensaml-security-api",
  "org.opensaml" % "opensaml-security-impl",
  "org.opensaml" % "opensaml-profile-api",
  "org.opensaml" % "opensaml-profile-impl",
  "org.opensaml" % "opensaml-messaging-api",
  "org.opensaml" % "opensaml-messaging-impl",
  "org.opensaml" % "opensaml-storage-impl",
  "org.opensaml" % "opensaml-xmlsec-impl",
  "org.opensaml" % "opensaml-storage-impl",
  "org.opensaml" % "opensaml-xmlsec-impl",
  "org.opensaml" % "opensaml-storage-impl",
  "org.opensaml" % "opensaml-messaging-impl",
  "org.opensaml" % "opensaml-profile-api"
).map(_ % "4.0.1")

dependencyOverrides ++= samlOverrides

//dependencyOverrides += "org.opensaml" % "opensaml-core-api" % "5.1.2"
excludeDependencies += "org.eclipse.jetty" % "jetty-io"
excludeDependencies += "org.eclipse.jetty" % "jetty-server"
excludeDependencies += "commons-collections" % "commons-collections"
excludeDependencies += "org.bouncycastle" % "bcpkix-jdk15on"
excludeDependencies += "org.bouncycastle" % "bcprov-jdk15on"
//excludeDependencies += "org.bouncycastle" % "bcpkix-jdk18on"
//excludeDependencies += "org.bouncycastle" % "bcprov-jdk18on"

versionGenerate := {
  log("version_metadata.json Generated")
  val versionFile = baseDirectory.value / "version_metadata.json"
  // val version:Int = version.value
  val json = s"""{"version": "$version"}"""
  0
}

downloadThirdPartyDeps := {
  log("Downloading third-party dependencies...")
  val status = Process(
    "wget -Nqi thirdparty-dependencies.txt -P /opt/third-party -c",
    baseDirectory.value / "support"
  ).!
  status
}

//https://www.devspace.sh/
//When you use Def.sequential to chain multiple tasks, the final result will be the type of the last task in the sequence.
devSpaceReload := Def
  .sequential(
    (Universal / packageBin),
    Def.task { Process("devspace run extract-archive").! }
  )
  .value

//-------------------------------------------------------------------------------------------------
// Run settings
//-------------------------------------------------------------------------------------------------

// Add UI Run hook to run UI alongside with API.
//   (Compile / run) is an input task
//   (Compile / run).toTask("") is a task

runBackend := {
  val runBackendTask: Def.Initialize[Task[Unit]] = (Compile / run).toTask("")
  val curState = state.value
  val newState = Project
    .extract(curState)
    .appendWithoutSession(
      Vector(PlayKeys.playRunHooks += UIRunHook(baseDirectory.value / "ui")),
      curState
    )
  Project.extract(newState).runInputTask((Compile / run), "", newState)
}

//-------------------------------------------------------------------------------------------------
// Test settings
//-------------------------------------------------------------------------------------------------

Global / concurrentRestrictions := Seq(Tags.limitAll(16))

val testParallelForks = SettingKey[Int](
  "testParallelForks",
  "Number of parallel forked JVMs, running tests"
)
testParallelForks := 4
val testShardSize = SettingKey[Int](
  "testShardSize",
  "Number of test classes, executed by each forked JVM"
)
testShardSize := 30

Global / concurrentRestrictions += Tags.limit(
  Tags.ForkedTestGroup,
  testParallelForks.value
)

def partitionTests(tests: Seq[TestDefinition], shardSize: Int): Seq[Group] =
  tests
    .sortWith(_.name.hashCode() < _.name.hashCode())
    .grouped(shardSize)
    .zipWithIndex map { case (tests, index) =>
    val options = ForkOptions().withRunJVMOptions(
      Vector(
        "-Xmx2g",
        "-XX:MaxMetaspaceSize=600m",
        "-XX:MetaspaceSize=200m",
        "-Dconfig.resource=application.test.conf"
      )
    )
    Group("testGroup" + index, tests, SubProcess(options))
  } toSeq

Test / parallelExecution := true
Test / fork := true
Test / testGrouping := partitionTests(
  (Test / definedTests).value,
  testShardSize.value
)

Test / javaOptions += "-Dconfig.resource=application.test.conf"
testOptions += Tests.Argument(TestFrameworks.JUnit, "-v", "-q", "-a")
testOptions += Tests.Filter(s => !s.contains("tasks.local"))

lazy val testLocal = inputKey[Unit]("Runs local provider tests")
lazy val testFast = inputKey[Unit]("Runs quick tests")
lazy val testUpgradeRetry = inputKey[Unit]("Runs retry tests")

def localTestSuiteFilter(name: String): Boolean =
  (name startsWith "tasks.local")
def quickTestSuiteFilter(name: String): Boolean =
  !(name.startsWith("tasks.local") ||
    name.startsWith("tasks.upgrade"))

def upgradeRetryTestSuiteFilter(name: String): Boolean =
  (name startsWith "tasks.upgrade")

// Skip auto-recompile of code in dev mode if AUTO_RELOAD=false
//lazy val autoReload = getBoolEnvVar("AUTO_RELOAD")

lazy val autoReload = true
playMonitoredFiles := {
  if (autoReload) playMonitoredFiles.value: @sbtUnchecked else Seq()
}

val grafanaGen: TaskKey[Unit] = taskKey[Unit](
  "generate dashboard.json"
)

grafanaGen := Def.taskDyn {
  val file = (Compile / resourceDirectory).value / "metric" / "Dashboard.json"
  Def.sequential(
    (Test / runMain)
      .toTask(s" controllers.GrafanaGenTest $file")
  )
}.value

//-----------------------------------------------------------------------------------
// UI Build Tasks
//  UI Build Tasks like clean node modules, npm install and npm run build
//-----------------------------------------------------------------------------------

// Execution status success.
val Success = 0

// Execution status failure.
val Error = 1

// Delete node_modules directory in the given path. Return 0 if success.
def cleanNodeModules(implicit dir: File): Int =
  Process("rm -rf node_modules", dir) !

// Execute `npm ci` command to install all node module dependencies. Return 0 if success.
def runNpmInstall(implicit dir: File): Int =
  if (cleanNodeModules != 0) throw new Exception("node_modules not cleaned up")
  //        if (!(base / "ui" / "node_modules").exists()
  else {
    println(
      "node version: " + Process("node" :: "--version" :: Nil).lineStream_!.head
    )
    println(
      "npm version: " + Process("npm" :: "--version" :: Nil).lineStream_!.head
    )
    println(
      "npm config get: " + Process(
        "npm" :: "config" :: "get" :: Nil
      ).lineStream_!.head
    )
    println(
      "npm cache verify: " + Process(
        "npm" :: "cache" :: "verify" :: Nil
      ).lineStream_!.head
    )
    Process("npm" :: "ci" :: "--legacy-peer-deps" :: Nil, dir).!
  }

// Execute `npm run build` command to build the production build of the UI code. Return 0 if success.
def runNpmBuild(implicit dir: File): Int =
  Process("npm run build-and-copy:prod", dir) !

def npmRunTest(implicit dir: File): Int =
  Process("npm run test", dir) !

clean := (clean dependsOn cleanFrontend).value

cleanFrontend := {
  log("Cleaning Frontend...")
  val status = Process("rm -rf node_modules dist", baseDirectory.value / "ui").!
  status
}

installFrontendDependencies := {
  log("Installing Frontend dependencies...")
  implicit val uiSource = baseDirectory.value / "ui"
  if (runNpmInstall != 0) throw new Exception("npm install failed")
}

frontendBuild := {
  implicit val uiSource = baseDirectory.value / "ui"
  if (runNpmBuild != 0) throw new Exception("UI Build crashed.")
}

frontendTests := {
  implicit val uiSource = baseDirectory.value / "ui"
  if (npmRunTest != 0) throw new Exception("UI Tests crashed.")
}

frontendBuild := frontendBuild.dependsOn(installFrontendDependencies).value

//Test/test := (Test/test).dependsOn(frontendTests).value
/// Execute frontend prod build task prior to play dist execution.
// If task A depends on task B, then task B will be executed first.

dist := (dist dependsOn frontendBuild).value

// // Execute frontend prod build task prior to play stage execution.
stage := (stage dependsOn frontendBuild).value

// // Execute frontend test task prior to play test execution.
//test := ((Test / test) dependsOn `ui-test`).value

//----------------------------------------------------------------------------------
// Packaging tasks
//----------------------------------------------------------------------------------
//Make SBT packaging depend on the UI build hook.

//target/universal/<project-name>.txz
Universal / packageXzTarball := (Universal / packageXzTarball)
  .dependsOn(frontendBuild, versionGenerate)
  .value

//target/universal/<project-name>.tgz
Universal / packageZipTarball := (Universal / packageZipTarball)
  .dependsOn(frontendBuild, versionGenerate)
  .value

// Being used by DevSpace tool to build an archive without building the UI
Universal / packageBin := (Universal / packageBin)
  .dependsOn(versionGenerate)
  .value

Docker / mappings := (Universal / mappings).value
//Universal / packageZipTarball / mappings += file("README") -> "README"

ThisBuild / semanticdbEnabled := true

ThisBuild / run / fork := true

Test / fork := true

javacOptions ++= Seq(
  "-encoding",
  "UTF-8",
  "-Xlint:-options",
  "-Xlint:unchecked",
  "-Xlint:deprecation",
  "-proc:only" // or "-proc:full" if you want full processing

)

name := """scala-dss-test"""
organization := "com.trust1team"
version := "0.0.1-SNAPSHOT"
scalaVersion := "2.13.8"

lazy val dssVersion                       = "5.10.1"
lazy val commonsIoVersion                 = "2.11.0"
lazy val commonsCodecVersion              = "1.15"

lazy val dssPades                   = "eu.europa.ec.joinup.sd-dss"          %   "dss-pades"                                   % dssVersion
lazy val dssXades                   = "eu.europa.ec.joinup.sd-dss"          %   "dss-asic-xades"                              % dssVersion
lazy val dssCades                   = "eu.europa.ec.joinup.sd-dss"          %   "dss-asic-cades"                              % dssVersion
lazy val dssService                 = "eu.europa.ec.joinup.sd-dss"          %   "dss-service"                                 % dssVersion
lazy val dssCommons                 = "eu.europa.ec.joinup.sd-dss"          %   "dss-utils-apache-commons"                    % dssVersion
lazy val dssParser                  = "eu.europa.ec.joinup.sd-dss"          %   "dss-crl-parser"                              % dssVersion
lazy val dssParserStream            = "eu.europa.ec.joinup.sd-dss"          %   "dss-crl-parser-stream"                       % dssVersion
lazy val dssTslValidation           = "eu.europa.ec.joinup.sd-dss"          %   "dss-tsl-validation"                          % dssVersion
lazy val dssPadesPdfBox             = "eu.europa.ec.joinup.sd-dss"          %   "dss-pades-pdfbox"                            % dssVersion
lazy val dssSpi                     = "eu.europa.ec.joinup.sd-dss"          %   "dss-spi"                                     % dssVersion
lazy val commonsIo                  = "commons-io"                          %   "commons-io"                                  % commonsIoVersion
lazy val commonsCodec               = "commons-codec"                       %   "commons-codec"                               % commonsCodecVersion

resolvers ++= Seq(
  "google" at "https://maven.google.com/",
  "CEF Digital" at "https://joinup.ec.europa.eu/nexus/content/groups/public/",
  "cefdigital" at "https://ec.europa.eu/cefdigital/artifact/content/repositories/esignaturedss/"
)

lazy val root = (project in file(".")).enablePlugins(PlayScala)
  .settings(
    libraryDependencies ++= Seq(
      guice,
      ws,
      caffeine,
      dssPades,
      dssXades,
      dssCades,
      dssService,
      dssCommons,
      dssParser,
      dssParserStream,
      dssTslValidation,
      dssPadesPdfBox,
      dssSpi,
      commonsIo,
      commonsCodec
    )
  )
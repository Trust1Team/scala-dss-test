package models

import play.api.libs.json.{Format, Json}

case class DataToSign(data: String)
object DataToSign {
  implicit val fmt: Format[DataToSign] = Json.format
}
package models

import play.api.libs.json.{Format, JsValue, Json}

case class DataToSign(data: String)
object DataToSign {
  implicit val fmt: Format[DataToSign] = Json.format
}
case class ApiResponse[A](success: Boolean = true, data: Option[A] = None, description: Option[String] = None, code: Option[Int] = None, stackTrace: Option[String] = None)
object ApiResponse {
  implicit def fmt[A](implicit fmtA: Format[A]): Format[ApiResponse[A]] = Json.format
  def success[A](data: A)(implicit fmt: Format[A]): JsValue = Json.toJson(ApiResponse[A](data = Some(data)))
  def failed(description: Option[String], code: Int, stackTrace: Option[String] = None): JsValue = Json.toJson(ApiResponse[String](success = false, description = description, code = Some(code), stackTrace = stackTrace))
}
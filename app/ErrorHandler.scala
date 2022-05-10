import models.ApiResponse
import play.api.Logging
import play.api.http.HttpErrorHandler
import play.api.mvc.Results._
import play.api.mvc.{RequestHeader, Result}
import play.shaded.ahc.io.netty.handler.codec.http.HttpResponseStatus

import scala.concurrent.Future

class ErrorHandler extends HttpErrorHandler with Logging {

  override def onClientError(request: RequestHeader, statusCode: Int, message: String): Future[Result] = {
    logger.trace(s"Request ${request.path} failed because of: '$message'")
    val msg = statusCode match {
      case 404 if message.isEmpty => s"Method ${request.method} on path ${request.path} does not exist"
      case _   => if (message.nonEmpty) message else HttpResponseStatus.valueOf(statusCode).reasonPhrase
    }
    Future.successful(Status(statusCode)(ApiResponse.failed(description = Some(msg), statusCode)))
  }

  override def onServerError(request: RequestHeader, ex: Throwable): Future[Result] = {
    logger.error(s"Error: ${ex.getMessage}", ex)
    Future.successful(InternalServerError(ApiResponse.failed(description = Some(ex.getMessage), code = 500)))
  }
}
package lifecycle

import akka.Done
import akka.actor.ActorSystem
import com.typesafe.config.ConfigRenderOptions
import play.api.inject.ApplicationLifecycle
import play.api.libs.json.Json
import play.api.{Configuration, Logging}
import services.SigningService

import java.time.{ZoneId, ZonedDateTime}
import javax.inject.{Inject, Named, Singleton}
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class ApplicationManager @Inject()(lifecycle: ApplicationLifecycle,
                                   signingService: SigningService)(implicit ec: ExecutionContext) extends Logging {

  // Shut-down hook
  lifecycle.addStopHook { () =>
    Future.successful(Done)
  }
  signingService.refreshTslRepositoryValidation
}
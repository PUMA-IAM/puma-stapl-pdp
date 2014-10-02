package puma.stapl.pdp

import puma.peputils.PDP
import puma.peputils.PDPResult
import puma.peputils.Environment
import puma.peputils.Subject
import puma.peputils.Object
import puma.peputils.Action
import puma.peputils.PDPDecision
import stapl.core._
import stapl.core.pdp.{PDP => InternalPDP}
import stapl.core.pdp.RequestCtx
import puma.peputils.attributes.Multiplicity
import puma.peputils.attributes.DataType
import java.util.Date
import org.joda.time.LocalDateTime
import puma.peputils.AttributeValueCollection
import puma.peputils.attributes.AttributeValue
import stapl.core.pdp.AttributeFinder
import grizzled.slf4j.Logging
import stapl.core.DenyOverrides
import stapl.core.pdp.RemoteEvaluator

/**
 * An adapter class from stapl.core.pdp.PDP to puma.peputils.PDP
 */
class StaplPDP extends PDP with Logging {
  
  // TODO preliminary implementation
  protected def pdp: InternalPDP = _pdp
  
  // Implemented as a lazy val so `pdp` can be overridden in test cases without `_pdp` being initialized.
  // Apparently vals get initialized even when they're overridden in a subclass and the subclass in instantiated.
  // This causes problems in test cases because the SubjectAttributeFinderModule tries to set up a DB connection.
  private lazy val _pdp = new InternalPDP({
    Policy("application-policy") := apply DenyOverrides to (
      RemotePolicy("central-puma-policy")
    )
  },
  {
    val evaluator = new RemoteEvaluator
    evaluator += new CentralPolicyRemoteEvaluatorModule
    evaluator
  })
  
  override final def evaluate(subject: Subject, obj: Object, action: Action, environment: Environment): PDPResult =
    try{
      pdp.evaluate(convert(subject, obj, action, environment)) match {
        case Result(Permit, _) => new PDPResult(PDPDecision.PERMIT, "ok")
        case Result(Deny, _) => new PDPResult(PDPDecision.DENY, "ok")
        case Result(NotApplicable, _) => new PDPResult(PDPDecision.NOT_APPLICABLE, "ok")
      }
    } catch {
      case e: Exception => 
        debug(s"Exception thrown during evaluation: $e", e)
        new PDPResult(PDPDecision.INDETERMINATE, "ok")
    }
  
  private def convert(subject: Subject, obj: Object, action: Action, environment: Environment): RequestCtx = {
    import scala.collection.JavaConversions._
    
    val request = new RequestCtx(subject.getId(), action.getId(), obj.getId())
    
    def addAttributes[A <: AttributeValue](obj: AttributeValueCollection[A], cType: AttributeContainerType){
	    for(value <- obj.getAttributeValues()){
	      request.allAttributes += (value.getIdWithoutPrefix(), cType) -> (
	        if (value.getMultiplicity() == Multiplicity.ATOMIC)
	          value.getDataType() match {
              case DataType.String => value.getValues().head.asInstanceOf[String]
	            case DataType.Boolean => value.getValues().head.asInstanceOf[Boolean]
	            case DataType.Double => value.getValues().head.asInstanceOf[Double]
	            case DataType.Integer => value.getValues().head.asInstanceOf[Int]
	            case DataType.DateTime => new LocalDateTime(value.getValues().head)
	          }
	        else
	          value.getDataType() match {
              case DataType.String => value.getValues().toSeq.asInstanceOf[Seq[String]]
	            case DataType.Boolean => value.getValues().toSeq.asInstanceOf[Seq[Boolean]]
	            case DataType.Double => value.getValues().toSeq.asInstanceOf[Seq[Double]]
	            case DataType.Integer => value.getValues().toSeq.asInstanceOf[Seq[Int]]
	            case DataType.DateTime => value.getValues().map(date => new LocalDateTime(date)).toSeq
	          })
	    }
    }
    
    addAttributes(subject, SUBJECT)
    addAttributes(obj, RESOURCE)
    addAttributes(action, ACTION)
    addAttributes(environment, ENVIRONMENT)
    
    request
  }
  
}
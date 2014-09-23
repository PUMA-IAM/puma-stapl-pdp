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

/**
 * An adapter class from stapl.core.pdp.PDP to puma.peputils.PDP
 */
class StaplPDP extends PDP {
  
  // TODO preliminary implementation
  protected val pdp = new InternalPDP(
    Rule("test") := deny
  )
  
  override final def evaluate(subject: Subject, obj: Object, action: Action, environment: Environment): PDPResult =
    try{
      pdp.evaluate(convert(subject, obj, action, environment)) match {
        case Result(Permit, _) => new PDPResult(PDPDecision.PERMIT, "ok")
        case Result(Deny, _) => new PDPResult(PDPDecision.DENY, "ok")
        case Result(NotApplicable, _) => new PDPResult(PDPDecision.NOT_APPLICABLE, "ok")
      }
    } catch {
      case e: Exception => new PDPResult(PDPDecision.INDETERMINATE, "ok")
    }
  
  private def convert(subject: Subject, obj: Object, action: Action, environment: Environment): RequestCtx = {
    import scala.collection.JavaConversions._
    
    val request = new RequestCtx(subject.getId(), action.getId(), obj.getId())
    
    def addAttributes[A <: AttributeValue](obj: AttributeValueCollection[A], cType: AttributeContainerType){
	    for(value <- obj.getAttributeValues()){
	      request.allAttributes += (value.getIdWithoutPrefix(), cType) -> (
	        if (value.getMultiplicity() == Multiplicity.ATOMIC)
	          value.getDataType() match {
	            case DataType.Boolean => value.getValues().head.asInstanceOf[Boolean]
	            case DataType.Double => value.getValues().head.asInstanceOf[Double]
	            case DataType.Integer => value.getValues().head.asInstanceOf[Int]
	            case DataType.String => value.getValues().head.asInstanceOf[String]
	            case DataType.DateTime => new LocalDateTime(value.getValues().head.asInstanceOf[Date])
	          }
	        else
	          value.getDataType() match {
	            case DataType.Boolean => value.getValues().map(_.asInstanceOf[Boolean]).toSeq
	            case DataType.Double => value.getValues().map(_.asInstanceOf[Double]).toSeq
	            case DataType.Integer => value.getValues().map(_.asInstanceOf[Int]).toSeq
	            case DataType.String => value.getValues().map(_.asInstanceOf[String]).toSeq
	            case DataType.DateTime => value.getValues().map(date => new LocalDateTime(date.asInstanceOf[Date])).toSeq
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
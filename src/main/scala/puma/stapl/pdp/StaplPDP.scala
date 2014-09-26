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

/**
 * An adapter class from stapl.core.pdp.PDP to puma.peputils.PDP
 */
class StaplPDP extends PDP with Logging /* TODO don't inherit BasicPolicy in final version */ with BasicPolicy {
  
  // TODO preliminary implementation
  protected lazy val pdp: InternalPDP = new InternalPDP({
    resource.type_ = SimpleAttribute("type", String)
    resource.creating_tenant = SimpleAttribute("creating-tenant", String)
    resource.owning_tenant = SimpleAttribute("owning-tenant", String)
    subject.tenant = ListAttribute(String)
    subject.assigned_tenants = ListAttribute("subject:assigned_tenants", String)
    subject.region = ListAttribute("subject:region", String)
    
    val centralPolicy =
      Policy("central-puma-policy") := when (resource.type_ === "document") apply DenyOverrides to(
        Policy("reading-deleting") := when (action.id === "read" | action.id === "delete") apply DenyOverrides to(
          Rule("1") := deny iff (!(resource.creating_tenant in subject.tenant)),
          Rule("default-permit:1") := permit
        ),
        Policy("creating") := when (action.id === "create") apply DenyOverrides to(
          Rule("default-permit:99") := permit
        )
      )
    
    val tenant3 =
      Policy("tenantsetid:3") := when ("3" in subject.tenant) apply DenyOverrides to(
        Policy("large-bank:read") := when (action.id === "read" & resource.type_ === "document") apply PermitOverrides to(
          Rule("191") := permit iff (resource.owning_tenant in subject.assigned_tenants),
          Rule("193") := deny
        ),
        Policy("large-bank:send") := when (action.id === "send" & resource.type_ === "document") apply PermitOverrides to(
          Rule("193") := permit
        )
      )
    
    val tenant4 =
      Policy("tenantsetid:4") := when ("4" in subject.tenant) apply DenyOverrides to(
        Policy("press-agency") := apply DenyOverrides to(
          Rule("press-agency:1") := deny iff (!("Europe" in subject.region)),
          Rule("press-agency:2") := permit
        )
      )
    
    Policy("global-puma-policy") := apply DenyOverrides to (
      centralPolicy,
      tenant3,
      tenant4
    )
  }, 
  {
    val finder = new AttributeFinder
    finder += new SubjectAttributeFinderModule
    finder
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
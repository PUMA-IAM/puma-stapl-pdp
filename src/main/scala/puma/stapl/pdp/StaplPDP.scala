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
import puma.rmi.pdp.mgmt.ApplicationPDPMgmtRemote
import java.io.PrintWriter
import java.io.FileNotFoundException
import java.io.UnsupportedEncodingException
import java.io.InputStream
import java.io.FileInputStream
import java.io.IOException
import org.apache.commons.io.FileUtils
import java.io.File
import stapl.parser.CompleteParser
import puma.peputils.PEP

/**
 * An adapter class from stapl.core.pdp.PDP to puma.peputils.PDP
 */
class StaplPDP(policyDir: String) extends PDP with PEP with ApplicationPDPMgmtRemote with Logging {
  
  protected var pdp: InternalPDP = _
  private val evaluator = new RemoteEvaluator
  evaluator += new CentralPolicyRemoteEvaluatorModule
  
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
  
  override final def isAuthorized(subject: Subject, obj: Object, action: Action, environment: Environment): Boolean =
    evaluate(subject, obj, action, environment).getDecision() match {
      case PDPDecision.PERMIT => 
        info("Authorization decision for " + getIds(subject, obj, action) + " was Permit")
        true
      case PDPDecision.DENY => 
        info("Authorization decision for " + getIds(subject, obj, action) + " was Deny")
        false
      case PDPDecision.INDETERMINATE => 
        warn("Authorization decision for " + getIds(subject, obj, action) + " was Indeterminate")
        false
      case PDPDecision.NOT_APPLICABLE => 
        info("Authorization decision for " + getIds(subject, obj, action) + " was Not Applicable")
        false
      case _ =>
        error("An unknown result was returned by the PDP")
        false
    }
  
  private def getIds(subject: Subject, obj: Object, action: Action) =
    "(" + subject.getId() + ", " + obj.getId() + ", " + action.getId() + ")"
  
  private def convert(subject: Subject, obj: Object, action: Action, environment: Environment): RequestCtx = {
    import scala.collection.JavaConversions._
    
    val request = new RequestCtx(subject.getId(), action.getId(), obj.getId())
    
    def addAttributes[A <: AttributeValue](obj: AttributeValueCollection[A], cType: AttributeContainerType){
	    for(value <- obj.getAttributeValues()){
	      val name = value.getIdWithoutPrefix()
	      request.allAttributes += {
	        if (value.getMultiplicity() == Multiplicity.ATOMIC)
	          value.getDataType() match {
              case DataType.String => SimpleAttribute(cType, name, String) -> value.getValues().head.asInstanceOf[String]
	            case DataType.Boolean => SimpleAttribute(cType, name, Bool) -> value.getValues().head.asInstanceOf[Boolean]
	            case DataType.Double => SimpleAttribute(cType, name, Number) -> value.getValues().head.asInstanceOf[Double]
	            case DataType.Integer => SimpleAttribute(cType, name, Number) -> value.getValues().head.asInstanceOf[Int]
	            case DataType.DateTime => SimpleAttribute(cType, name, DateTime) -> new LocalDateTime(value.getValues().head)
	          }
	        else
	          value.getDataType() match {
              case DataType.String => ListAttribute(cType, name, String) -> value.getValues().toSeq.asInstanceOf[Seq[String]]
	            case DataType.Boolean => ListAttribute(cType, name, Bool) -> value.getValues().toSeq.asInstanceOf[Seq[Boolean]]
	            case DataType.Double => ListAttribute(cType, name, Number) -> value.getValues().toSeq.asInstanceOf[Seq[Double]]
	            case DataType.Integer => ListAttribute(cType, name, Number) -> value.getValues().toSeq.asInstanceOf[Seq[Int]]
	            case DataType.DateTime => ListAttribute(cType, name, DateTime) -> value.getValues().map(date => new LocalDateTime(date)).toSeq
	          }
	      }
	    }
    }
    
    addAttributes(subject, SUBJECT)
    addAttributes(obj, RESOURCE)
    addAttributes(action, ACTION)
    addAttributes(environment, ENVIRONMENT)
    
    request
  }
  
  
  /***********************
   * APPLICATION PDP MGMT
   ***********************/

  private var status = "NOT INITIALIZED"
  
  override def getStatus(): String =  status

  private val applicationPolicyFilename = policyDir + "application-policy.stapl"
  
  override def loadApplicationPolicy(policy: String) {
    val writer: PrintWriter = 
      try {
        new PrintWriter(applicationPolicyFilename, "UTF-8")
      } catch {
        case e: FileNotFoundException =>
          error("Application policy file not found when writing new application policy", e)
          return
        case e: UnsupportedEncodingException =>
          error("Unsupported encoding when writing new application policy", e)
          return
      }
    writer.print(policy)
    writer.close()
    info("Succesfully reloaded application policy")
    this.reload()
  }
  
  private var remoteAccessIsEnabled = false
  
  /**
   * Doesn't do anything right now...
   */
  override def setRemoteDBAccess(enabled: java.lang.Boolean) {
    info("Setting remote access to DB from this PDP to " + enabled)
    this.remoteAccessIsEnabled = enabled
    info("Reloading PDP...")
    this.reload()
  }

  override def reload() {
    // just set up a new PDP
    val policyString: String =
      try {
        FileUtils.readFileToString(new File(applicationPolicyFilename))
      } catch {
        case e: FileNotFoundException =>
          error("Could not reload PDP: application policy file not found", e)
          status = "APPLICATION POLICY FILE NOT FOUND"
          return
      }
    val policy = CompleteParser.parse(policyString, Nil)
    this.pdp = new InternalPDP(policy, evaluator)
    info("Reloaded application PDP [remote access = " + this.remoteAccessIsEnabled.toString() + "]")
    status = "OK"
  }

  override def getApplicationPolicy(): String = {
    try {
      FileUtils.readFileToString(new File(applicationPolicyFilename))
    } catch {
      case e: IOException =>
        warn("IOException when reading application policy file", e)
        return "IOException"
    }
  }

  override def getId(): String = "" + this.hashCode()
  
  // initialize the PDP on startup
  reload()
  
}
package puma.stapl.pdp

import stapl.core.pdp.RemoteEvaluatorModule
import stapl.core.Result
import stapl.core.pdp.EvaluationCtx
import grizzled.slf4j.Logging
import stapl.core.Deny
import stapl.core.Permit
import stapl.core.NotApplicable
import stapl.core.String
import stapl.core.Bool
import stapl.core.Number
import stapl.core.ConcreteValue
import stapl.core.NumberImpl
import stapl.core.IntSeqImpl
import stapl.core.LongSeqImpl
import stapl.core.DoubleSeqImpl
import stapl.core.DateTime
import stapl.core.AttributeContainerType
import stapl.core.SUBJECT
import stapl.core.RESOURCE
import stapl.core.ENVIRONMENT
import stapl.core.ACTION
import stapl.core.DateTimeImpl
import stapl.core.SimpleAttribute
import stapl.core.ListAttribute
import puma.rest.client.CentralPDPClient
import puma.rest.domain.AttributeValue
import puma.rest.domain.DataType
import puma.rest.domain.Multiplicity
import puma.rest.domain.ObjectType
import puma.rest.domain.ResponseType

object CentralPolicyRemoteEvaluatorModule {
  
  private val CENTRAL_PUMA_PDP_HOST = "puma-central-puma-pdp-stapl";
  private val CENTRAL_PUMA_PDP_PORT = "8080";

}

class CentralPolicyRemoteEvaluatorModule extends RemoteEvaluatorModule with Logging {
  
  import CentralPolicyRemoteEvaluatorModule._
  
  private var client: CentralPDPClient = new CentralPDPClient(s"$CENTRAL_PUMA_PDP_HOST:$CENTRAL_PUMA_PDP_PORT", "stapl")

  override def findAndEvaluate(policyId: String, ctx: EvaluationCtx): Option[Result] = {
    if(policyId == "central-puma-policy") {
      val result = try {
          client.evaluate(getAttributeValues(ctx))
      } catch {
        case e: Exception => 
          warn("Exception when contacting the remote PUMA PDP", e)
          ResponseType.DENY
      }
      result match {
        case ResponseType.DENY => Some(Deny)
        case ResponseType.PERMIT => Some(Permit)
        case ResponseType.NOT_APPLICABLE => Some(NotApplicable)
        case ResponseType.INDETERMINATE => sys.error(s"""Result of remote policy with id "$policyId" was indeterminate""")
      }
    }
    else None
  }
  
  private def getAttributeValues(ctx: EvaluationCtx): java.util.List[AttributeValue] = {
    import scala.collection.JavaConverters._
    
    (for((attribute, cvalue) <- ctx.cachedAttributes.toSeq) yield {
      attribute match {
        case SimpleAttribute(cType, name, aType) =>
          val value = new AttributeValue(getDataType(cvalue), toObjectType(cType), getMultiplicity(cvalue), name)
          value.getDataType() match {
            case DataType.STRING => value.addToStringValues(cvalue.representation.asInstanceOf[String])
            case DataType.BOOLEAN => value.addToBooleanValues(cvalue.representation.asInstanceOf[Boolean])
            case DataType.DOUBLE => value.addToDoubleValues(cvalue.representation.asInstanceOf[Double])
            case DataType.INTEGER => value.addToIntValues(cvalue.representation.asInstanceOf[Long].toInt)
            case DataType.DATETIME => value.addToDatetimeValues(cvalue.asInstanceOf[DateTimeImpl].dt.toDate.getTime())
          }
          value
        case ListAttribute(cType, name, aType) =>
          val value = new AttributeValue(getDataType(cvalue), toObjectType(cType), getMultiplicity(cvalue), name)
          value.getDataType() match {
            case DataType.STRING => value.setStringValues(cvalue.representation.asInstanceOf[Seq[String]].asJava)
            case DataType.BOOLEAN => value.setBooleanValues(cvalue.representation.asInstanceOf[Seq[java.lang.Boolean]].asJava)
            case DataType.DOUBLE => value.setDoubleValues(cvalue.representation.asInstanceOf[Seq[java.lang.Double]].asJava)
            case DataType.INTEGER => value.setIntValues(cvalue.representation.asInstanceOf[Seq[java.lang.Number]].map(_.intValue).asJava.asInstanceOf[java.util.List[java.lang.Integer]]) // sigh...
            case DataType.DATETIME => value.setDatetimeValues(cvalue.representation.asInstanceOf[Seq[DateTimeImpl]].map(_.dt.toDate.getTime()).asJava.asInstanceOf[java.util.List[java.lang.Long]]) // :'(
          }
          value
      }
    }).asJava
  }
  
  private def getDataType(value: ConcreteValue): DataType = value.aType match {
    case String => DataType.STRING
    case Bool => DataType.BOOLEAN
    case Number if value.representation.isInstanceOf[Long] => DataType.INTEGER
    case Number if value.representation.isInstanceOf[Double] => DataType.DOUBLE
    case Number if value.isInstanceOf[IntSeqImpl] => DataType.INTEGER
    case Number if value.isInstanceOf[LongSeqImpl] => DataType.INTEGER
    case Number if value.isInstanceOf[DoubleSeqImpl] => DataType.DOUBLE
    case DateTime => DataType.DATETIME
    case other => sys.error(s"Type $other cannot be converted to a DataTypeP")
  }
  
  private def getMultiplicity(value: ConcreteValue): Multiplicity = 
    if (value.isList) Multiplicity.GROUPED
    else Multiplicity.ATOMIC
  
  private def toObjectType(cType: AttributeContainerType): ObjectType = cType match {
    case SUBJECT => ObjectType.SUBJECT
    case RESOURCE => ObjectType.RESOURCE
    case ACTION => ObjectType.ACTION
    case ENVIRONMENT  => ObjectType.ENVIRONMENT
  }
  
  /**
   * This operation is not supported.
   */
  override def findAndIsApplicable(policyId: String, ctx: EvaluationCtx): Option[Boolean] = 
    throw new UnsupportedOperationException("`isApplicable` is not supported on the central puma pdp")
}
package puma.stapl.pdp

import stapl.core.pdp.RemoteEvaluatorModule
import stapl.core.Result
import stapl.core.pdp.EvaluationCtx
import org.apache.thrift.transport.TTransport
import org.apache.thrift.transport.TSocket
import org.apache.thrift.transport.TTransportException
import org.apache.thrift.protocol.TProtocol
import grizzled.slf4j.Logging
import org.apache.thrift.protocol.TBinaryProtocol
import stapl.core.Deny
import puma.thrift.pdp.AttributeValueP
import stapl.core.Permit
import stapl.core.NotApplicable
import stapl.core.String
import puma.thrift.pdp.RemotePDPService
import puma.thrift.pdp.ResponseTypeP
import stapl.core.AttributeType
import puma.thrift.pdp.DataTypeP
import stapl.core.Bool
import stapl.core.Number
import stapl.core.ConcreteValue
import stapl.core.NumberImpl
import stapl.core.IntSeqImpl
import stapl.core.LongSeqImpl
import stapl.core.DoubleSeqImpl
import stapl.core.DateTime
import stapl.core.AttributeContainerType
import puma.thrift.pdp.ObjectTypeP
import stapl.core.SUBJECT
import stapl.core.RESOURCE
import stapl.core.ENVIRONMENT
import stapl.core.ACTION
import puma.thrift.pdp.MultiplicityP
import stapl.core.DateTimeImpl
import org.apache.thrift.TException

object CentralPolicyRemoteEvaluatorModule {
  
  private val CENTRAL_PUMA_PDP_HOST = "puma-central-puma-pdp";

  private val CENTRAL_PUMA_PDP_THRIFT_PORT = 9091;
}

class CentralPolicyRemoteEvaluatorModule extends RemoteEvaluatorModule with Logging {
  
  import CentralPolicyRemoteEvaluatorModule._
  
  private var client: RemotePDPService.Client = null

  private var transport: TTransport = null

  setupCentralPUMAPDPConnection()


  /**
   * Idempotent helper function to set up the RMI connection to the central
   * PUMA PDP.
   */
  private def setupCentralPUMAPDPConnection() {
    if (!isCentralPUMAPDPConnectionOK()) {
      // set up Thrift
      transport = new TSocket(CENTRAL_PUMA_PDP_HOST, CENTRAL_PUMA_PDP_THRIFT_PORT)
      try {
        transport.open()
      } catch {
        case e: TTransportException =>
          warn("FAILED to reach the central PUMA PDP", e)
          e.printStackTrace();
      }

      val protocol: TProtocol = new TBinaryProtocol(transport)
      client = new RemotePDPService.Client(protocol)
      info("Set up Thrift client to Central PUMA PDP")
    }
  }

  /**
   * Helper function that returns whether the RMI connection to the central
   * PUMA PDP is set up or not.
   */
  private def isCentralPUMAPDPConnectionOK() = client != null && transport != null && transport.isOpen()

  /**
   * Resets the central PUMA connection so that isCentralPUMAPDPConnectionOK()
   * returns false and the connection can be set up again using
   * setupCentralPUMAPDPConnection().
   */
  private def resetCentralPUMAPDPConnection() {
    transport.close()
    client = null
  }

  override def findAndEvaluate(policyId: String, ctx: EvaluationCtx): Option[Result] = {
    if(policyId == "central-puma-policy") {
      setupCentralPUMAPDPConnection()
      if (!isCentralPUMAPDPConnectionOK()) {
        error("The RMI connection to the remote PUMA PDP was not set up => default deny")
        Some(Deny)
      } else {
        val result = try {
          client.evaluateP(getAttributeValuePs(ctx))
        } catch {
          case e: TException => 
            warn("TException when contacting the remote PUMA PDP, trying to set up connection again", e)
            resetCentralPUMAPDPConnection()
            setupCentralPUMAPDPConnection()
            try {
              client.evaluateP(getAttributeValuePs(ctx))
            } catch {
              case e: TException => 
                warn("Again TException when contacting the remote PUMA PDP => default deny", e)
                ResponseTypeP.DENY
            }
        }
        result match {
          case ResponseTypeP.DENY => Some(Deny)
          case ResponseTypeP.PERMIT => Some(Permit)
          case ResponseTypeP.NOT_APPLICABLE => Some(NotApplicable)
          case ResponseTypeP.INDETERMINATE => sys.error(s"""Result of remote policy with id "$policyId" was indeterminate""")
        }
      }
    }
    else None
  }
  
  private def getAttributeValuePs(ctx: EvaluationCtx): java.util.List[AttributeValueP] = {
    import scala.collection.JavaConverters._
    
    (for(((name, cType), value) <- ctx.attributes) yield {
      val valueP = new AttributeValueP(getDataTypeP(value), toObjectTypeP(cType), getMultiplicity(value), name)
      if (valueP.getMultiplicity() == MultiplicityP.ATOMIC)
        valueP.getDataType() match {
          case DataTypeP.STRING => valueP.addToStringValues(value.representation.asInstanceOf[String])
          case DataTypeP.BOOLEAN => valueP.addToBooleanValues(value.representation.asInstanceOf[Boolean])
          case DataTypeP.DOUBLE => valueP.addToDoubleValues(value.representation.asInstanceOf[Double])
          case DataTypeP.INTEGER => valueP.addToIntValues(value.representation.asInstanceOf[Long].toInt)
          case DataTypeP.DATETIME => valueP.addToDatetimeValues(value.asInstanceOf[DateTimeImpl].dt.toDate.getTime())
        }
      else
        valueP.getDataType() match {
          case DataTypeP.STRING => valueP.setStringValues(value.representation.asInstanceOf[Seq[String]].asJava)
          case DataTypeP.BOOLEAN => valueP.setBooleanValues(value.representation.asInstanceOf[Seq[java.lang.Boolean]].asJava)
          case DataTypeP.DOUBLE => valueP.setDoubleValues(value.representation.asInstanceOf[Seq[java.lang.Double]].asJava)
          case DataTypeP.INTEGER => valueP.setIntValues(value.representation.asInstanceOf[Seq[java.lang.Number]].map(_.intValue).asJava.asInstanceOf[java.util.List[java.lang.Integer]]) // sigh...
          case DataTypeP.DATETIME => valueP.setDatetimeValues(value.representation.asInstanceOf[Seq[DateTimeImpl]].map(_.dt.toDate.getTime()).asJava.asInstanceOf[java.util.List[java.lang.Long]]) // :'(
        }
      valueP
    }).asJava
  }
  
  private def getDataTypeP(value: ConcreteValue): DataTypeP = value.aType match {
    case String => DataTypeP.STRING
    case Bool => DataTypeP.BOOLEAN
    case Number if value.representation.isInstanceOf[Long] => DataTypeP.INTEGER
    case Number if value.representation.isInstanceOf[Double] => DataTypeP.DOUBLE
    case Number if value.isInstanceOf[IntSeqImpl] => DataTypeP.INTEGER
    case Number if value.isInstanceOf[LongSeqImpl] => DataTypeP.INTEGER
    case Number if value.isInstanceOf[DoubleSeqImpl] => DataTypeP.DOUBLE
    case DateTime => DataTypeP.DATETIME
    case other => sys.error(s"Type $other cannot be converted to a DataTypeP")
  }
  
  private def getMultiplicity(value: ConcreteValue): MultiplicityP = 
    if (value.isList) MultiplicityP.GROUPED
    else MultiplicityP.ATOMIC
  
  private def toObjectTypeP(cType: AttributeContainerType): ObjectTypeP = cType match {
    case SUBJECT => ObjectTypeP.SUBJECT
    case RESOURCE => ObjectTypeP.RESOURCE
    case ACTION => ObjectTypeP.ACTION
    case ENVIRONMENT  => ObjectTypeP.ENVIRONMENT
  }
  
  /**
   * This operation is not supported.
   */
  override def findAndIsApplicable(policyId: String, ctx: EvaluationCtx): Option[Boolean] = 
    throw new UnsupportedOperationException("`isApplicable` is not supported on the central puma pdp")
}
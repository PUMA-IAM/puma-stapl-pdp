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

/**
 * An adapter class from stapl.core.pdp.PDP to puma.peputils.PDP
 */
class StaplPDP extends PDP {
  
  // TODO preliminary implementation
  private val pdp = new InternalPDP(
    Rule("test") := deny
  )
  
  override def evaluate(subject: Subject, obj: Object, action: Action, environment: Environment): PDPResult = new PDPResult(PDPDecision.PERMIT, "ok")
  
}
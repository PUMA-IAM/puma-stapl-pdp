package puma.stapl.pdp

import org.scalatest.FunSuite
import stapl.core._
import stapl.core.pdp.PDP
import puma.peputils.Subject
import puma.peputils.Object
import puma.peputils.Action
import puma.peputils.Environment
import puma.peputils.PDPDecision
import puma.peputils.attributes.SubjectAttributeValue
import puma.peputils.attributes.EnvironmentAttributeValue
import puma.peputils.attributes.Multiplicity
import java.util.Date
import org.joda.time.LocalDateTime

class StaplPDPTest extends FunSuite {
  
  test("a policy that always denies") {
    val testpdp = new StaplPDP {
      override lazy val pdp = new PDP(
        Rule("test") := deny
      )
    }
    val decision = testpdp.evaluate(new Subject("subjectID"), new Object("objectID"), new Action("actionID"), new Environment()).getDecision()
    assert(decision === PDPDecision.DENY)
  }
  
  test("a policy that always permits") {
    val testpdp = new StaplPDP {
      override lazy val pdp = new PDP(
        Rule("test") := permit
      )
    }
    val decision = testpdp.evaluate(new Subject("subjectID"), new Object("objectID"), new Action("actionID"), new Environment()).getDecision()
    assert(decision === PDPDecision.PERMIT)
  }
  
  test("a request that's not applicable") {
    val testpdp = new StaplPDP with BasicPolicy {
      override lazy val pdp = new PDP(
        Policy("test") := when (subject.id === "Unknown") apply PermitOverrides to (
          Rule("testrule") := permit
        )
      )
    }
    val decision = testpdp.evaluate(new Subject("subjectID"), new Object("objectID"), new Action("actionID"), new Environment()).getDecision()
    assert(decision === PDPDecision.NOT_APPLICABLE)
  }
  
  test("a request with an attribute missing") {
    val testpdp = new StaplPDP with BasicPolicy {
      subject.name = SimpleAttribute(String)
      override lazy val pdp = new PDP(
        Policy("test") := when (subject.name === "Unknown") apply PermitOverrides to (
          Rule("testrule") := permit
        )
      )
    }
    val decision = testpdp.evaluate(new Subject("subjectID"), new Object("objectID"), new Action("actionID"), new Environment()).getDecision()
    assert(decision === PDPDecision.INDETERMINATE)
  }
  
  test("a request with an atomic attribute") {
    val testpdp = new StaplPDP with BasicPolicy {
      subject.name = SimpleAttribute(String)
      override lazy val pdp = new PDP(
        Policy("test") := when (subject.name === "jasper") apply PermitOverrides to (
          Rule("testrule") := permit
        )
      )
    }
    val subject = new Subject("subjectID")
    subject.addAttributeValue(new SubjectAttributeValue("name", Multiplicity.ATOMIC, "jasper"))
    val decision = testpdp.evaluate(subject, new Object("objectID"), new Action("actionID"), new Environment()).getDecision()
    assert(decision === PDPDecision.PERMIT)
  }
  
  test("a request with a grouped attribute") {
    val testpdp = new StaplPDP with BasicPolicy {
      environment.locations = ListAttribute(String)
      override lazy val pdp = new PDP(
        Policy("test") := apply PermitOverrides to (
          Rule("testrule") := permit iff ("testclass" in environment.locations)
        )
      )
    }
    val env = new Environment()
    val locations = new EnvironmentAttributeValue("locations", Multiplicity.GROUPED)
    locations.addValue("here")
    locations.addValue("testclass")
    locations.addValue("there")
    env.addAttributeValue(locations)
    val decision = testpdp.evaluate(new Subject("subjectID"), new Object("objectID"), new Action("actionID"), env).getDecision()
    assert(decision === PDPDecision.PERMIT)
  }
  
  test("a request with a DATETIME attribute") {
    val testpdp = new StaplPDP with BasicPolicy {
      val env = environment
      env.currentTime = SimpleAttribute(DateTime)
      val now = new LocalDateTime()
      val millisago = now.minusMillis(100)
      val millisahead = now.plusMillis(100)
      override lazy val pdp = new PDP(
        Policy("test") := apply PermitOverrides to (
          Rule("testrule") := permit iff ((millisago lteq env.currentTime) & (millisahead gteq env.currentTime))
        )
      )
    }
    val env = new Environment()
    env.addAttributeValue(new EnvironmentAttributeValue("currentTime", Multiplicity.ATOMIC, new Date))
    val decision = testpdp.evaluate(new Subject("subjectID"), new Object("objectID"), new Action("actionID"), env).getDecision()
    // if dates are converted back and forth in a correct way `env.currentTime` has 
    // to be very close to `now` and the request will be permitted
    assert(decision === PDPDecision.PERMIT)
  }
}
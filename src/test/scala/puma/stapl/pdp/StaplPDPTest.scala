/*package puma.stapl.pdp

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
import puma.peputils.attributes.ActionAttributeValue
import puma.peputils.attributes.ObjectAttributeValue

class StaplPDPTest extends FunSuite {
  
  test("a policy that always denies") {
    val testpdp = new StaplPDP {
      override val pdp = new PDP(
        Rule("test") := deny
      )
    }
    val decision = testpdp.evaluate(new Subject("subjectID"), new Object("objectID"), new Action("actionID"), new Environment()).getDecision()
    assert(decision === PDPDecision.DENY)
  }
  
  test("a policy that always permits") {
    val testpdp = new StaplPDP {
      override val pdp = new PDP(
        Rule("test") := permit
      )
    }
    val decision = testpdp.evaluate(new Subject("subjectID"), new Object("objectID"), new Action("actionID"), new Environment()).getDecision()
    assert(decision === PDPDecision.PERMIT)
  }
  
  test("a request that's not applicable") {
    val testpdp = new StaplPDP with BasicPolicy {
      override val pdp = new PDP(
        Policy("test") := apply PermitOverrides to (
          Rule("testrule") := permit iff (subject.id === "Unknown")
        )
      )
    }
    val decision = testpdp.evaluate(new Subject("subjectID"), new Object("objectID"), new Action("actionID"), new Environment()).getDecision()
    assert(decision === PDPDecision.NOT_APPLICABLE)
  }
  
  test("a request with an attribute missing") {
    val testpdp = new StaplPDP with BasicPolicy {
      subject.name = SimpleAttribute(String)
      override val pdp = new PDP(
        Policy("test") := apply PermitOverrides to (
          Rule("testrule") := permit iff subject.name === "Unknown",
          Rule("default") := deny
        )
      )
    }
    val decision = testpdp.evaluate(new Subject("subjectID"), new Object("objectID"), new Action("actionID"), new Environment()).getDecision()
    assert(decision === PDPDecision.INDETERMINATE)
  }
  
  test("a request with an atomic STRING attribute") {
    val testpdp = new StaplPDP with BasicPolicy {
      subject.name = SimpleAttribute(String)
      override val pdp = new PDP(
        Policy("test") := apply PermitOverrides to (
          Rule("testrule") := permit iff (subject.name === "jasper"),
          Rule("default") := deny
        )
      )
    }
    val subject = new Subject("subjectID")
    subject.addAttributeValue(new SubjectAttributeValue("name", Multiplicity.ATOMIC, "jasper"))
    val decision = testpdp.evaluate(subject, new Object("objectID"), new Action("actionID"), new Environment()).getDecision()
    assert(decision === PDPDecision.PERMIT)
  }
  
  test("a request with a grouped STRING attribute") {
    val testpdp = new StaplPDP with BasicPolicy {
      environment.locations = ListAttribute(String)
      override val pdp = new PDP(
        Policy("test") := apply PermitOverrides to (
          Rule("testrule") := permit iff ("testclass" in environment.locations),
          Rule("default") := deny
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
  
  test("a request with an atomic INT attribute") {
    val testpdp = new StaplPDP with BasicPolicy {
      subject.num = SimpleAttribute(Number)
      override val pdp = new PDP(
        Policy("test") := apply PermitOverrides to (
          Rule("testrule") := permit iff (subject.num === 5),
          Rule("default") := deny
        )
      )
    }
    val subject = new Subject("subjectID")
    subject.addAttributeValue(new SubjectAttributeValue("num", Multiplicity.ATOMIC, 5))
    val decision = testpdp.evaluate(subject, new Object("objectID"), new Action("actionID"), new Environment()).getDecision()
    assert(decision === PDPDecision.PERMIT)
  }
  
  test("a request with a grouped INT attribute") {
    val testpdp = new StaplPDP with BasicPolicy {
      action.numbers = ListAttribute(Number)
      override val pdp = new PDP(
        Policy("test") := apply PermitOverrides to (
          Rule("testrule") := permit iff (5 in action.numbers),
          Rule("default") := deny
        )
      )
    }
    val action = new Action("actionID")
    val numbers = new ActionAttributeValue("numbers", Multiplicity.GROUPED)
    numbers.addValue(new java.lang.Integer(2))
    numbers.addValue(new java.lang.Integer(5))
    numbers.addValue(new java.lang.Integer(7))
    action.addAttributeValue(numbers)
    val decision = testpdp.evaluate(new Subject("subjectID"), new Object("objectID"), action, new Environment()).getDecision()
    assert(decision === PDPDecision.PERMIT)
  }
  
  test("a request with an atomic DOUBLE attribute") {
    val testpdp = new StaplPDP with BasicPolicy {
      resource.num = SimpleAttribute(Number)
      override val pdp = new PDP(
        Policy("test") := apply PermitOverrides to (
          Rule("testrule") := permit iff (resource.num === 5.5),
          Rule("default") := deny
        )
      )
    }
    val obj = new Object("objectID")
    obj.addAttributeValue{val v = new ObjectAttributeValue("num", Multiplicity.ATOMIC); v.addValue(5.5); v}
    val decision = testpdp.evaluate(new Subject("subjectID"), obj, new Action("actionID"), new Environment()).getDecision()
    assert(decision === PDPDecision.PERMIT)
  }
  
  test("a request with a grouped DOUBLE attribute") {
    val testpdp = new StaplPDP with BasicPolicy {
      environment.numbers = ListAttribute(Number)
      override val pdp = new PDP(
        Policy("test") := apply PermitOverrides to (
          Rule("testrule") := permit iff (5.5 in environment.numbers),
          Rule("default") := deny
        )
      )
    }
    val env = new Environment()
    val numbers = new EnvironmentAttributeValue("numbers", Multiplicity.GROUPED)
    numbers.addValue(2.8)
    numbers.addValue(5.5)
    numbers.addValue(7.3)
    env.addAttributeValue(numbers)
    val decision = testpdp.evaluate(new Subject("subjectID"), new Object("objectID"), new Action("actionID"), env).getDecision()
    assert(decision === PDPDecision.PERMIT)
  }
  
  test("a request with an atomic BOOLEAN attribute") {
    val testpdp = new StaplPDP with BasicPolicy {
      subject.bool = SimpleAttribute(Bool)
      override val pdp = new PDP(
        Policy("test") := apply PermitOverrides to (
          Rule("testrule") := permit iff (subject.bool),
          Rule("default") := deny
        )
      )
    }
    val subject = new Subject("subjectID")
    subject.addAttributeValue(new SubjectAttributeValue("bool", Multiplicity.ATOMIC, true))
    val decision = testpdp.evaluate(subject, new Object("objectID"), new Action("actionID"), new Environment()).getDecision()
    assert(decision === PDPDecision.PERMIT)
  }
  
  test("a request with a grouped BOOLEAN attribute") {
    val testpdp = new StaplPDP with BasicPolicy {
      environment.bools = ListAttribute(Bool)
      override val pdp = new PDP(
        Policy("test") := apply PermitOverrides to (
          Rule("testrule") := permit iff (true in environment.bools),
          Rule("default") := deny
        )
      )
    }
    val env = new Environment()
    val bools = new EnvironmentAttributeValue("bools", Multiplicity.GROUPED)
    bools.addValue(false)
    bools.addValue(true)
    bools.addValue(false)
    env.addAttributeValue(bools)
    val decision = testpdp.evaluate(new Subject("subjectID"), new Object("objectID"), new Action("actionID"), env).getDecision()
    assert(decision === PDPDecision.PERMIT)
  }
  
  test("a request with an atomic DATETIME attribute") {
    val testpdp = new StaplPDP with BasicPolicy {
      val env = environment
      env.currentTime = SimpleAttribute(DateTime)
      val now = new LocalDateTime()
      //val millisago = now.minusMillis(100)
      val millisahead = now.plusMillis(100)
      override val pdp = new PDP(
        Policy("test") := apply PermitOverrides to (
          Rule("testrule") := permit iff ((now lteq env.currentTime) & (millisahead gteq env.currentTime)),
          Rule("default") := deny
        )
      )
    }
    val env = new Environment()
    env.addAttributeValue(new EnvironmentAttributeValue("currentTime", Multiplicity.ATOMIC, new Date))
    val decision = testpdp.evaluate(new Subject("subjectID"), new Object("objectID"), new Action("actionID"), env).getDecision()
    // if dates are converted back and forth in a correct way `env.currentTime` has 
    // to be very close to `now` and the request will be permitted
    // (also test it this way cause the users of the StaplPDP might not use joda-time)
    assert(decision === PDPDecision.PERMIT)
  }
  
  test("a request with a grouped DATETIME attribute") {
    val now = new LocalDateTime()
    val testpdp = new StaplPDP with BasicPolicy {
      val env = environment
      env.currentTime = ListAttribute(DateTime)
      override val pdp = new PDP(
        Policy("test") := apply PermitOverrides to (
          Rule("testrule") := permit iff (now in env.currentTime),
          Rule("default") := deny
        )
      )
    }
    val env = new Environment()
    env.addAttributeValue(new EnvironmentAttributeValue("currentTime", Multiplicity.GROUPED, now.toDate()))
    val decision = testpdp.evaluate(new Subject("subjectID"), new Object("objectID"), new Action("actionID"), env).getDecision()
    assert(decision === PDPDecision.PERMIT)
  }
}*/
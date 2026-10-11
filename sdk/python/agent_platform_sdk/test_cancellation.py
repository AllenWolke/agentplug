import copy
import unittest
from agent_platform_sdk.cancellation import read_cancellation_state, CancellationEvidenceError

class CancellationTest(unittest.TestCase):
    def proof(self):
        return {"version":"cancellation-state/v1","disposition":"verified","progress":{"version":"cancellation-compensation/v1","cancellation_id":"a"*64,"phase":"complete","stop_confirmed":True,"total":2,"compensated":1,"no_effect":1,"unresolved":0,"needs_attention":0}}
    def test_bare_agent_stop_is_not_business_completion(self):
        self.assertFalse(read_cancellation_state("cancelled").complete)
        self.assertTrue(read_cancellation_state("cancelled",self.proof()).complete)
    def test_incomplete_and_forged_counts_are_denied(self):
        for field,value in (("stop_confirmed",False),("unresolved",1),("total",True),("no_effect",-1),("phase","compensating")):
            proof=copy.deepcopy(self.proof());proof["progress"][field]=value
            with self.assertRaises(CancellationEvidenceError):read_cancellation_state("cancelled",proof)
    def test_private_fields_are_not_returned(self):
        proof=self.proof();proof["progress"]["before_image"]={"secret":"teaching-private"}
        self.assertNotIn("before_image",read_cancellation_state("cancelled",proof).progress)

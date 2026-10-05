"""Optional P7 local admission companion; original service/kernel are preserved."""
from protocol7_application import Application as ExactHeightApplication
from protocol7_treasury import COMMAND_MAGIC,result
from protocol7_admission import preflight,FUTURE_OWNER_HEIGHTS
class Application(ExactHeightApplication):
    def check_tx(self,raw):
        with self.lock:
            self._ready()
            if type(raw) is bytes and raw[:8]==COMMAND_MAGIC:
                if self.height>=64:return result(7)
                return preflight(self.g,self.state,raw,self.height+1,self.worker)
            return super().check_tx(raw)
    def info(self):
        v=super().info();v['name']='1soft-protocol7-owner-admission-development';v['owner_admission_heights']=FUTURE_OWNER_HEIGHTS
        return v

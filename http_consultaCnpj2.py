# -*- encoding: utf-8 -*-

import re
import urllib2, httplib, socket
import os.path
import logging
import libxml2
import xmlsec
import suds.bindings
import xml.etree.ElementTree as ET
from suds.sax.text import Raw
from suds.client import Client
from uuid import uuid4
from lxml import etree
from suds.transport.http import HttpTransport, Reply, TransportError
from suds.plugin import MessagePlugin
from suds.sax.element import Element as E
from suds.sax.attribute import Attribute
logging.basicConfig(level=logging.INFO)
logging.getLogger('suds.client').setLevel(logging.DEBUG)

class base_nfse(object):

    def __init__(self, arquivo, senha):
        self.arquivo = arquivo
        self.senha = senha

    def _checar_certificado(self):
        if not os.path.isfile(self.arquivo):
            raise Exception('Caminho do certificado nao existe.')

    def _inicializar_cripto(self):
        libxml2.initParser()
        libxml2.substituteEntitiesDefault(1)

        xmlsec.init()
        xmlsec.cryptoAppInit(None)
        xmlsec.cryptoInit()

    def finalizar_cripto(self):
        xmlsec.cryptoShutdown()
        xmlsec.cryptoAppShutdown()
        xmlsec.shutdown()

        libxml2.cleanupParser()


    def _save_pfx_certificate(self):
        pfx_tmp = '/tmp/' + uuid4().hex
        arq_temp = open(pfx_tmp, 'w')
        arq_temp.write(base64.b64decode(self.certificate))
        arq_temp.close()
        return pfx_tmp

    def converte_pfx_pem(self, pfx_stream, senha):
        try:
            certificado = crypto.load_pkcs12(pfx_stream, senha)
            privada = crypto.dump_privatekey(crypto.FILETYPE_PEM,
                certificado.get_privatekey())
            certificado = crypto.dump_certificate(crypto.FILETYPE_PEM,
                certificado.get_certificate())
        except Exception as e:
            if len(e.message) == 1 and len(e.message[0]) == 3 and \
                e.message[0][2] == 'mac verify failure':
                raise Exception('Senha inválida')
        raise
        return certificado, privada

    def render(self, base_path, template_path, **kwargs):
        #import pudb; pu.db
        env = Environment(loader=FileSystemLoader(os.path.join(base_path, 'templates')))
        env.filters["normalize"] = filters.normalize_str
        env.filters["format_percent"] = filters.format_percent
        env.filters["format_datetime"] = filters.format_datetime
        env.filters["format_date"] = filters.format_date

        template = env.get_template(template_path)

        # TODO Remover espaços e possíveis tags vazias
        xml = template.render(**kwargs)
        parser = etree.XMLParser(remove_blank_text=True, remove_comments=True)
        elem = etree.fromstring(xml, parser=parser)
        return etree.tostring(elem)

    def assina_xml(self, xml, reference, arquivo, chave):
        self._checar_certificado()
        self._inicializar_cripto()
        try:
            doc_xml = libxml2.parseMemory(
                xml.encode('utf-8'), len(xml.encode('utf-8')))

            signNode = xmlsec.TmplSignature(doc_xml, xmlsec.transformInclC14NId(),
                                            xmlsec.transformRsaSha1Id(), None)
            
            doc_xml.getRootElement().addChild(signNode)
            
            refNode = signNode.addReference(xmlsec.transformSha1Id(),
                                            None, reference, None)
            
            refNode.addTransform(xmlsec.transformEnvelopedId())
            refNode.addTransform(xmlsec.transformInclC14NId())
            keyInfoNode = signNode.ensureKeyInfo()
            keyInfoNode.addX509Data()

            dsig_ctx = xmlsec.DSigCtx()
            chave = xmlsec.cryptoAppKeyLoad(filename=str(arquivo),
                                            format=xmlsec.KeyDataFormatPkcs12,
                                            pwd=str(chave),
                                            pwdCallback=None,
                                            pwdCallbackCtx=None)

            dsig_ctx.signKey = chave
            dsig_ctx.sign(signNode)

            status = dsig_ctx.status
            dsig_ctx.destroy()

            if status != xmlsec.DSigStatusSucceeded:
                raise RuntimeError(
                    'Erro ao realizar a assinatura do arquivo; status: "' +
                    str(status) +
                    '"')
            NAMESPACE_SIG = 'http://www.w3.org/2000/09/xmldsig#'
            xpath = doc_xml.xpathNewContext()
            xpath.xpathRegisterNs('sig', NAMESPACE_SIG)
            certificados = xpath.xpathEval(
                '//sig:X509Data/sig:X509Certificate')
            for i in range(len(certificados) - 1):
                certificados[i].unlinkNode()
                certificados[i].freeNode()

            xml = doc_xml.serialize()
            return xml
        finally:
            doc_xml.freeDoc()
            #self._finalizar_cripto() # erro : urllib2.URLError: <urlopen error _ssl.c:320: Invalid SSL protocol variant specified.>

    def valida_schema(self, xml, arquivo_xsd):
        '''Função que valida um XML usando lxml do Python via arquivo XSD'''
        # Carrega o esquema XML do arquivo XSD
        xsd = etree.XMLSchema(file = arquivo_xsd)
        # Converte o XML passado em XML do lxml
        xml = etree.fromstring(str(xml))
        # Verifica a validade do xml
        erros = []
        if not xsd(xml):
            # Caso tenha erros, cria uma lista de erros
            for erro in xsd.error_log:
                erros.append({
                    'message' : erro.message,
                    'domain' : erro.domain,
                    'type' : erro.type,
                    'level' : erro.level,
                    'line' : erro.line,
                    'column' : erro.column,
                    'filename' : erro.filename,
                    'domain_name': erro.domain_name,
                    'type_name' : erro.type_name,
                    'level_name' : erro.level_name
                })
                print "erro %s, linha %s" % (erro.message, erro.line)
        # Retorna os erros, sendo uma lista vazia caso não haja erros
        return erros


class HTTPSClientAuthHandler(urllib2.HTTPSHandler):
    def __init__(self, key, cert):
        urllib2.HTTPSHandler.__init__(self)
        self.key = key
        self.cert = cert

    def https_open(self, req):
        #Rather than pass in a reference to a connection class, we pass in
        # a reference to a function which, for all intents and purposes,
        # will behave as a constructor
        return self.do_open(self.getConnection, req)

    def getConnection(self, host, timeout=300):
        return httplib.HTTPSConnection(host,
                                       key_file=self.key,
                                       cert_file=self.cert)


class HTTPSClientCertTransport(HttpTransport):
    def __init__(self, key, cert, *args, **kwargs):
        HttpTransport.__init__(self, *args, **kwargs)
        self.key = key
        self.cert = cert

    def u2open(self, u2request):
        """
        Open a connection.
        @param u2request: A urllib2 request.
        @type u2request: urllib2.Requet.
        @return: The opened file-like urllib2 object.
        @rtype: fp
        """
        tm = self.options.timeout
        url = urllib2.build_opener(HTTPSClientAuthHandler(self.key, self.cert))
        if self.u2ver() < 2.6:
            socket.setdefaulttimeout(tm)
            return url.open(u2request)
        else:
            return url.open(u2request, timeout=tm)

class EnvelopeFixer(MessagePlugin): 

    def sending(self, context):
        # removendo prefixo
        context.envelope = re.sub( 'ns[0-9]:', '', context.envelope )
        context.envelope = re.sub( '<SOAP-ENV:Header/>', '', str(context.envelope) )
        context.envelope = re.sub( '</VersaoSchema>', '</MensagemXML>', str(context.envelope) )
        context.envelope = re.sub( '<VersaoSchema>', '<VersaoSchema>1</VersaoSchema><MensagemXML>', str(context.envelope) )
        return context.envelope

    def marshalled(self, context): 
        #print context.envelope.str()       
        envelope = context.envelope    
        envelope.name = 'Envelope'
        envelope.setPrefix('soap12')
        envelope.nsprefixes = {
           'xsi' : 'http://www.w3.org/2001/XMLSchema-instance', 
           'soap12': 'http://www.w3.org/2003/05/soap-envelope',
           'xsd' : 'http://www.w3.org/2001/XMLSchema'
           
        }
        body_ele = envelope.getChildren()[1]
        body_ele.setPrefix("soap12")
        consulta = envelope.getChildren()[1][0]
        consulta.set("xmlns", "http://www.prefeitura.sp.gov.br/nfe")
        return Raw(context)

# These lines enable debug logging; remove them once everything works.
import logging
logging.basicConfig(level=logging.INFO)
logging.getLogger('suds.client').setLevel(logging.DEBUG)
logging.getLogger('suds.transport').setLevel(logging.DEBUG)
logging.getLogger('suds.xsd.schema').setLevel(logging.DEBUG)
logging.getLogger('suds.wsdl').setLevel(logging.DEBUG)

certificado = '/home/carlos/ats/clientes_server/ats/certificado_ats.pfx'
chave = 'ats2015cer'
host = 'nfe.prefeitura.sp.gov.br'
uri = '/ws/lotenfe.asmx?wsdl'

cert_temp = open(certificado, 'r').read()

pfx_tmp = '/tmp/' + uuid4().hex
arq_temp = open(pfx_tmp, 'w')
arq_temp.write(cert_temp)
arq_temp.close()

suds.bindings.binding.envns = ('SOAP-ENV',
    'http://www.w3.org/2003/05/soap-envelope')

base = base_nfse(pfx_tmp, chave)

t = HTTPSClientCertTransport('/home/carlos/ats/clientes_server/ats/atskey2.pem',
                             '/home/carlos/ats/clientes_server/ats/atscert.pem')

envelope = EnvelopeFixer()

c = Client('https://nfe.prefeitura.sp.gov.br/ws/lotenfe.asmx?wsdl',
    location='https://nfe.prefeitura.sp.gov.br/ws/lotenfe.asmx',
    timeout=300,
    transport = t, plugins=[envelope])

#, plugins=[envelope]
#headers=headers,
# remove o cabecalho do SOAP    
#, nosend=True

#c.options.prettyxml = True   

#    
    
#print c

#xml_send = open('/home/carlos/ats/pyxmlsec.xml', 'r')

xml = open('/home/carlos/ats/consulta_cnpj.xml','r')
xml_send = xml.read()
                  
#xml_send = "<p1:ConsultaCNPJRequest><CPFCNPJRemetente><CNPJ>08382545000111</CNPJ></CPFCNPJRemetente></Cabecalho><CNPJContribuinte><CNPJ>64533847000114</CNPJ></CNPJContribuinte></p1:ConsultaCNPJRequest>"
xml_send = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><p1:PedidoConsultaCNPJ xmlns:p1=\"http://www.prefeitura.sp.gov.br/nfe\"><Cabecalho Versao=\"1\"><CPFCNPJRemetente><CNPJ>08382545000111</CNPJ></CPFCNPJRemetente></Cabecalho><CNPJContribuinte><CNPJ>64533847000114</CNPJ></CNPJContribuinte></p1:PedidoConsultaCNPJ>"
 
xml_send = Raw(xml_send)                                      
                                            
reference = ""
xml_signed = base.assina_xml(xml_send, reference, pfx_tmp, str(chave))

arq_temp = open('/home/carlos/ats/xml_assinado.xml', 'w')
arq_temp.write(xml_signed)
arq_temp.close()

"""
message = \
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"\
"<soap12:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""\
"xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap12=\"http://www.w3.org/2003/05/soap-envelope\">"\
"<soap12:Body>" + xml_send + \
"</soap12:Body>"\
"</soap12:Envelope>"    
"""

#TODO - arrumar para pasta do sistema
#valida_schema = base.valida_schema(xml_signed, '/home/carlos/ats/doc/fiscal/NFSe_SP/schemas/nfse/PedidoEnvioLoteRPS_v01.xsd')

valida_schema = base.valida_schema(xml_signed, '/home/carlos/ats/doc/fiscal/NFSe_SP/schemas/nfse/PedidoConsultaCNPJ_v01.xsd')

if len(valida_schema):
    erros = "Erro(s) no XML: \n"
    for erro in valida_schema:
        erros += erro['type_name'] + ': ' + erro['message'] + '\n'
    raise ValueError(erros)

#xml_signed = xml_signed.replace(
#                    '<?xml version="1.0" encoding="UTF-8"?>',
#                    '<VersaoSchema>1</VersaoSchema><MensagemXML>')

#xml_signed = xml_signed.replace(
#                    '</p1:PedidoConsultaCNPJ>',
#                    '</p1:PedidoConsultaCNPJ></MensagemXML>')

print xml_signed
xml_pronto = xml_signed
 
arq_temp = open('/home/carlos/ats/xml_soap.xml', 'w')
arq_temp.write(xml_pronto)
arq_temp.close()

#import pudb;pu.db

#arq_temp = open('/home/carlos/ats/xml_soap.xml', 'r')
#xml_pronto = arq_temp.read()
#xml_p = ET.ElementTree(xml_pronto)
#xml_str = ET.tostring(xml_pronto, encoding='utf8', method='xml')


try:
    #parser = etree.XMLParser(remove_blank_text=True)
    #xml_envia = etree.XML(xml_pronto, parser=parser)
    x = c.service.ConsultaCNPJ(xml_pronto)
finally:
    base.finalizar_cripto()

"""
arq_temp = open('/home/carlos/ats/retorno.xml', 'w')
arq_temp.write(x)
arq_temp.close()
"""

print x

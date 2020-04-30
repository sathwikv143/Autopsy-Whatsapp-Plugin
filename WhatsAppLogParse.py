import jarray
import inspect
import os
import sys
import string
import re
from java.lang import Class
from java.lang import System
from java.sql  import DriverManager, SQLException
from java.util.logging import Level
from java.util import ArrayList
from java.io import File
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.casemodule.services import Blackboard


# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the analysis.
class WhatsAppParseIngestModuleFactory(IngestModuleFactoryAdapter):

    moduleName = "WhatsApp Desktop App Analyzer"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Module That Parses WhatsApp log file"

    def getModuleVersionNumber(self):
        return "1.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return WhatsAppParseIngestModule()


# Data Source-level ingest module.  One gets created per data source.
class WhatsAppParseIngestModule(DataSourceIngestModule):

    _logger = Logger.getLogger(WhatsAppParseIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self):
        self.context = None

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/latest/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    def startUp(self, context):
        self.context = context

    # extract time stamp from each line passed
    def time(self,line):
        timestamp_rex = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}")
        res = timestamp_rex.search(line)
        if res:
            stamp = res.group()
            return stamp


    # extract hostname from the line i.e., the name of the computer
    def get_hostname(self,line):
        name_beg = line.find("hostname")+11
        name_end = line.find("\"",name_beg+1)
        hostname = ''.join(line[name_beg:name_end])
        return hostname


    # get phone number from the line passed
    def get_c_num(self,line):
        if "@c.us" in line and len(line) > 10:
            num_beg = line.find("@c.us")-13
            num_end = line.find("@c.us")
            num = str(int(''.join(filter(str.isdigit, line[num_beg:num_end])))).strip()
            if num: return str(num)

    def get_g_num(self, line):
        if "@g.us" in line:
            num_beg = line.find("@g.us")-23
            num_end = line.find("@g.us")-11
            num = str(int(''.join(filter(str.isdigit, line[num_beg:num_end])))).strip()
            if num: return str(num)


    # get status of chat: composing, paused, recording
    def chat_state(self, line):
        state_beg = line.find("action")+17
        state_end = line.find("\"",state_beg+1)
        state = ''.join(line[state_beg:state_end])
        if state: return state


    # get online status
    def online_status(self, line):
        action_beg = line.find("action")+16
        action_end = line.find("\"",action_beg+1)
        status = ''.join(line[action_beg:action_end])
        if status: return status


    # get what message is sent
    def get_message(self, line):
        msg_beg = line.find("action")+15
        msg_end = line.find(",",msg_beg+1)
        msg = ''.join(line[msg_beg:msg_end])
        if msg: return msg


    # get if msg is deleted
    def delete(self, line):
        del_beg = line.find("action")+12
        del_end = line.find(",",del_beg+1)
        delt = ''.join(line[del_beg:del_end])
        if delt: return delt


    # get if number is blocked or not
    def block(self, line):
        block_beg = line.find("action")+13
        block_end = line.find(",",block_beg+1)
        blocked = ''.join(line[block_beg:block_end])
        if blocked == "true":
            block = self.get_c_num(line)
            if block: return block+" blocked"
        if blocked == "false":
            block = self.get_c_num(line)
            if block: return block+" unblocked"


    # get battery status
    def battery(self, line):
        battery_beg = line.find("action")+15
        battery_end = line.find(",",battery_beg+1)
        battery = ''.join(line[battery_beg:battery_end])
        if battery: return battery


    # get group creation and deletion
    def group_action(self, line):
        grp_beg = line.find("action")+13
        grp_end = line.find("\"",grp_beg+1)
        grp = ''.join(line[grp_beg:grp_end])
        if grp == "create":
            return "group created"
        elif grp == "delete":
            return "group deleted"
        elif "@c.us" in line:
            return "Participant added: "+self.get_c_num(line)


    # get user actions on "about" and "stories"
    def get_status(self, line):
        status_beg = line.find("action")+14
        status_end = line.find("\"",status_beg+1)
        status = ''.join(line[status_beg:status_end])
        if status == "set":
            return "Suspect modified ABOUT"
        elif "@c.us" and "read" in line:
            return "Suspect read story of :"+self.get_c_num(line)


    # get suspect reading a msg
    def get_read_msg(self, line):
        if "read" in line:
            return "Read msg from: "+str(self.get_c_num(line))
        if "delete" in line:
            return "Delete msg of: "+str(self.get_g_num(line))


    # suspect sending msg in group or individually
    def get_send_media(self, line):
        if "@c.us" in line:
            return "Message sent individually: "+self.get_c_num(line)
        elif "@g.us" in line:
            return "Message sent in group: "+self.get_g_num(line)


    # get received media
    def get_rcv_media(self, line):
        if "chat" in line:
            if "c.us" and "g.us" in line:
                text = self.get_g_num(line)+" Text received"
                if text: return text
            if "c.us" in line and "g.us" not in line:
                text = self.get_c_num(line)+" Text received"
                if text: return text

        elif "image" in line:
            if "c.us" and "g.us" in line:
                image = self.get_g_num(line)+" Image received"
                if image: return image
            if "c.us" in line and "g.us" not in line:
                image = self.get_c_num(line)+" Image received"
                if image: return image

        elif "video" in line and "status" not in line:
            if "c.us" and "g.us" in line:
                video = self.get_g_num(line)+" Video received"
                if video: return video
            if "c.us" in line and "g.us" not in line:
                video = self.get_c_num(line)+" Video received"
                if video: return video


    # get EOF of the file
    def get_eof_position(self,file_handle):
        original_position = file_handle.tell()
        eof_position = file_handle.seek(0, 2)
        file_handle.seek(original_position)
        return eof_position    

    # get all the printable characters from the file stream passed
    def find_printable(self,stream):
        printable = set(string.printable)
        found_str = ""
        data = open(str(stream),"rb")
        eof = self.get_eof_position(data)
        while eof != data.tell():
            d = data.read(1024*4)
            if not d:
                data.close()
                break
            for char in d:
                if char in printable:
                    found_str += char
                elif len(found_str) >= 4:
                    yield found_str+"\n"
                    found_str = ""
                else:
                    found_str = ""


    # create a new attribute
    def createAttribute(self, attributeName, attributeType, attributeDescription):
        skCase = Case.getCurrentCase().getSleuthkitCase()
        try:
            if "string" == attributeType:
                attributeId = skCase.addArtifactAttributeType(attributeName, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, attributeDescription)
                return skCase.getAttributeType(attributeName)
            else:
                attributeId = skCase.addArtifactAttributeType(attributeName, BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, attributeDescription)
                return skCase.getAttributeType(attributeName)
        except:     
            return skCase.getAttributeType(attributeName)


    # create a new artifact
    def createArtifact(self, artifactName, artifactDescription):
        skCase = Case.getCurrentCase().getSleuthkitCase();
        try:
             artId = skCase.addArtifactType(artifactName, artifactDescription)
             return skCase.getArtifactTypeID(artifactName)
        except:     
             return skCase.getArtifactTypeID(artifactName)


    # routine
    def insert_art_att(self, file, artId, artDes, attrId, attrDes, attrObj, line):
        
        moduleName = WhatsAppParseIngestModuleFactory.moduleName
        blackboard = Case.getCurrentCase().getServices().getBlackboard()

        art = self.createArtifact(artId,artDes)
        artifact = file.newArtifact(art)
        attributes = ArrayList()
        
        attId = self.createAttribute(attrId,"string",attrDes)
        attributes.add(BlackboardAttribute(attId,moduleName,attrObj))
        
        attId = self.createAttribute("TSK_TIME_STAMP","string","time stamp")
        attributes.add(BlackboardAttribute(attId,moduleName,self.time(line)))
        
        artifact.addAttributes(attributes)

        # try:
        #     blackboard.indexArtifact(art)
        # except Blackboard.BlackboardException as e:
        #     self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

    
    # Processing the data source
    def process(self, dataSource, progressBar):

        # we don't know how much work there is yet
        progressBar.switchToIndeterminate()

        # Use blackboard class to index blackboard artifacts for keyword search
        blackboard = Case.getCurrentCase().getServices().getBlackboard()

        # Find files named contacts.db, regardless of parent path
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, r"%.log")

        numFiles = len(files)
        progressBar.switchToDeterminate(numFiles)
        fileCount = 0
        temporaryDirectory = os.path.join(Case.getCurrentCase().getTempDirectory(), "WhatsApp_Parse")
        try:
            os.mkdir(temporaryDirectory)
        except:
            pass

        for file in files:

            # Check if the user pressed cancel while we were busy
            if self.context.isJobCancelled():
                return IngestModule.ProcessResult.OK

            fileCount += 1

            extractedFile = os.path.join(temporaryDirectory, str(file.getId()) + "-" + file.getName())
            ContentUtils.writeToFile(file, File(extractedFile))

            for line in self.find_printable(extractedFile):
                if "action,presence" in line:
                    status = self.online_status(line)
                    self.insert_art_att(file, "TSK_ONLINE_STATUS", "Online Status", "TSK_ONLINE_STATUS", "status", status, line)

                if "action,chatstate" in line:
                    name = self.chat_state(line)
                    self.insert_art_att(file, "TSK_CHAT_STATE", "Chat State", "TSK_CHAT_STATE_NAME", "state", name, line)

                if "action,message" in line:
                    msg = self.get_message(line)
                    self.insert_art_att(file, "TSK_MSG", "Sent Media", "TSK_MSG_TYPE", "msg type", msg, line)

                if "action,msgs" in line:
                    delt = self.delete(line)
                    self.insert_art_att(file, "TSK_MSG_DELETE", "Message Deleted", "TSK_DELETE", "action", delt, line)

                if "action,block" in line:
                    block = self.block(line)
                    self.insert_art_att(file, "TSK_BLOCKED", "Contacts Blocked", "TSK_IF_BLOCKED", "if blocked", block, line)

                if "action,battery" in line:
                    battery = self.battery(line)
                    self.insert_art_att(file, "TSK_BATTERY", "Battery Percent", "TSK_BATTERY_PERCENT", "battery", battery, line)

                if "action,group" in line:
                    grp = self.group_action(line)
                    self.insert_art_att(file, "TSK_GROUP", "Group creation", "TSK_GRP_ACTION", "action", grp, line)

                if "action,status" in line:
                    status = self.get_status(line)
                    self.insert_art_att(file, "TSK_STATUS_INFO", "Status/Story Actions", "TSK_STATUS_ACTION", "action", status, line)

                if "action,chat," in line:
                    read = self.get_read_msg(line)
                    self.insert_art_att(file, "TSK_READ_INFO", "Reading Message", "TSK_READ", "action", read, line)

                if "Media:sendToChat" in line: 
                    sent = self.get_send_media(line)
                    self.insert_art_att(file, "TSK_MSG_SEND", "Sending Message", "TSK_SENT", "action", sent, line)

                if "action,msg,relay" in line:
                    rcv = self.get_rcv_media(line)
                    self.insert_art_att(file, "TSK_RCV_MEDIA", "Receiving Message", "TSK_RCV", "action", rcv, line)
                    

        # After all databases, post a message to the ingest messages in box.
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "WhatsAppParse Analyzer", "Found %d files" % fileCount)
        IngestServices.getInstance().postMessage(message)

        return IngestModule.ProcessResult.OK
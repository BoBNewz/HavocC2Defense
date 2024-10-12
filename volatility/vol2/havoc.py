"""
Plugin to recover Havoc headers in memory.

	- Magic Value
	- AgentID
	- CommandID
	- RequestID
	- AES key
	- AES IV

@author:   (@BoBNewz)
"""

import re
import volatility.plugins.common as common
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.debug as debug
import binascii

class HavocExtractor():
    def __init__(self):
        self.magic_value = re.compile(
            b'\xde\xad\xbe\xef....\x00\x00\x00\x63\x00\x00\x00\x00',
            re.DOTALL
        )

    def extract_data(self, outfd, address_space, proc):
        chunk_size = 0x100000

        for addr_tuple in address_space.get_available_addresses():
            addr, size = addr_tuple

            memory_chunk = address_space.zread(addr, min(chunk_size, size))
            if not memory_chunk:
                continue

            for match in self.magic_value.finditer(memory_chunk):
                
                header = binascii.hexlify(memory_chunk[match.start():match.end() + 48])
                
                magicvalue = header[:8]
                agentID = header[8:16]
                commandID = header[16:24]
                requestID = header[24:32]
                aeskey = header[32:96]
                aesiv = header[96:128]
                
                outfd.write("{} : {}\n".format("Magic Value", magicvalue))
                outfd.write("{} : {}\n".format("AgentID", agentID))
                outfd.write("{} : {}\n".format("CommandID", commandID))
                outfd.write("{} : {}\n".format("RequestID", requestID))
                outfd.write("{} : {}\n".format("AES Key", aeskey))
                outfd.write("{} : {}\n".format("AES IV", aesiv))
   
        return 0

class Havoc(common.AbstractWindowsCommand):

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        config.add_option("PID", short_option='p', default=None, help="Process ID to filter", action="store", type="int")

    def calculate(self):

        addr_space = utils.load_as(self._config)
        return tasks.pslist(addr_space)

    def render_text(self, outfd, data):

        outfd.write("\n{}\n{}\n\n".format("Plugin to recover Havoc headers in memory", "Author: @BoBNewz"))
		
        outfd.write("{:<10} {:<20}\n".format("PID", "Process Name"))
        outfd.write("="*30 + "\n")
        

        if self._config.PID is not None:
            for proc in data:
                if self._config.PID == proc.UniqueProcessId:
                    outfd.write("{:<10} {:<20}\n\n".format(proc.UniqueProcessId, proc.ImageFileName))
                    self.extract_havoc_data(outfd, proc)
                    break
        else:
            debug.error("You need to provide a PID.")

    def extract_havoc_data(self, outfd, proc):

        extractor = HavocExtractor()

        process_as = proc.get_process_address_space()

        if not process_as:
            debug.error("Canno't find address space for the process : {0}".format(proc.UniqueProcessId))
            return

        extractor.extract_data(outfd, process_as, proc)

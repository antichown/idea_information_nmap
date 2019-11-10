
local http = require "http"
local shortport = require "shortport"
local vulns = require "vulns"
local stdnse = require "stdnse"
local string = require "string"

description = [[JetBrains .idea project directory sensitive information]]

author = "0x94"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"info"}


portrule = shortport.http

local deg=false

action = function(host, port)
  local vuln = {
    title = "JetBrains .idea project directory sensitive information",
    state = vulns.STATE.NOT_VULN,
    description = [[
	.idea folder to gather sensitive information]]
  }


local vuln=""
options = {header={}}  options['header']['User-Agent'] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.97 Safari/537.36"    
local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
local url = stdnse.get_script_args(SCRIPT_NAME..".0x94") or "/.idea/workspace.xml"
local response = http.generic_request(host, port, "GET", "/.idea/workspace.xml", options)

if response.status == 200 and string.match(response.body, "project version")  then

	local uri = "/.idea/webServers.xml"
    	local response_vuln = http.get(host, port, uri)

    	vuln="Vulnerable\n"
	
	if (response.status == 200) then
	 
	 if string.match(response_vuln.body, "project version") then
	   vuln=vuln..response_vuln.body
	   end
	end
        	
	return vuln
	
 end

end

 


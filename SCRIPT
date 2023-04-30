NSE SCRIPT 
author = "Marc Ruef, marc.ruef-at-computec.ch, https://www.computec.ch/mruef/"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "safe", "vuln"}

local stdnse = require("stdnse")
local have_stringaux, stringaux = pcall(require, "stringaux")
local strsplit = (have_stringaux and stringaux or stdnse).strsplit

portrule = function(host, port)
	if port.version.product ~= nil and port.version.product ~= "" then
		return true
	else
		stdnse.print_debug(1, "vulscan: No version detection data available. Analysis not possible.")
	end
end

action = function(host, port)
	local prod = port.version.product	-- product name
	local ver = port.version.version	-- product version
	local struct = "[{id}] {title}\n"	-- default report structure
	local db = {}				-- vulnerability database
	local db_link = ""			-- custom link for vulnerability databases
	local vul = {}				-- details for the vulnerability
	local v_count = 0			-- counter for the vulnerabilities
	local s = ""				-- the output string

	stdnse.print_debug(1, "vulscan: Found service " .. prod)

	-- Go into interactive mode
	if nmap.registry.args.vulscaninteractive == "1" then
		stdnse.print_debug(1, "vulscan: Enabling interactive mode ...")
		print("The scan has determined the following product:")
		print(prod)
		print("Press Enter to accept. Define new string to override.")
		local prod_override = io.stdin:read'*l'

		if string.len(prod_override) ~= 0 then
			prod = prod_override
			stdnse.print_debug(1, "vulscan: Product overwritten as " .. prod)
		end
	end

	-- Read custom report structure
	if nmap.registry.args.vulscanoutput ~= nil then
		if nmap.registry.args.vulscanoutput == "details" then
			struct = "[{id}] {title}\nMatches: {matches}, Prod: {product}, Ver: {version}\n{link}\n\n"
		elseif nmap.registry.args.vulscanoutput == "listid" then
			struct = "{id}\n"
		elseif nmap.registry.args.vulscanoutput == "listlink" then
			struct = "{link}\n"
		elseif nmap.registry.args.vulscanoutput == "listtitle" then
			struct = "{title}\n"
		else
			struct = nmap.registry.args.vulscanoutput
		end

		stdnse.print_debug(1, "vulscan: Custom output structure defined as " .. struct)
	end

	-- Read custom database link
	if nmap.registry.args.vulscandblink ~= nil then
		db_link = nmap.registry.args.vulscandblink
		stdnse.print_debug(1, "vulscan: Custom database link defined as " .. db_link)
	end

	if nmap.registry.args.vulscandb then
		stdnse.print_debug(1, "vulscan: Using single mode db " .. nmap.registry.args.vulscandb .. " ...")
		vul = find_vulnerabilities(prod, ver, nmap.registry.args.vulscandb)
		if #vul > 0 then
			s = s .. nmap.registry.args.vulscandb
			if db_link ~= "" then s = s .. " - " .. db_link end
			s = s .. ":\n" .. prepare_result(vul, struct, db_link) .. "\n\n"
		end
	else
		-- Add your own database, if you want to include it in the multi db mode
		db[1] = {name="VulDB",			file="scipvuldb.csv",		url="https://vuldb.com",			link="https://vuldb.com/id.{id}"}
		db[2] = {name="MITRE CVE",		file="cve.csv",			url="https://cve.mitre.org",			link="https://cve.mitre.org/cgi-bin/cvename.cgi?name={id}"}
		db[3] = {name="SecurityFocus",		file="securityfocus.csv",	url="https://www.securityfocus.com/bid/",	link="https://www.securityfocus.com/bid/{id}"}
		db[4] = {name="IBM X-Force",		file="xforce.csv",		url="https://exchange.xforce.ibmcloud.com",	link="https://exchange.xforce.ibmcloud.com/vulnerabilities/{id}"}
		db[5] = {name="Exploit-DB",		file="exploitdb.csv",		url="https://www.exploit-db.com",		link="https://www.exploit-db.com/exploits/{id}"}
		db[6] = {name="OpenVAS (Nessus)",	file="openvas.csv",		url="http://www.openvas.org",			link="https://www.tenable.com/plugins/nessus/{id}"}
		db[7] = {name="SecurityTracker",	file="securitytracker.csv",	url="https://www.securitytracker.com",		link="https://www.securitytracker.com/id/{id}"}
		db[8] = {name="OSVDB",			file="osvdb.csv",		url="http://www.osvdb.org",			link="http://www.osvdb.org/{id}"}

		stdnse.print_debug(1, "vulscan: Using multi db mode (" .. #db .. " databases) ...")
		for i,v in ipairs(db) do
			vul = find_vulnerabilities(prod, ver, v.file)

			s = s .. v.name .. " - " .. v.url .. ":\n"
			if #vul > 0 then
					v_count = v_count + #vul
					s = s .. prepare_result(vul, struct, v.link) .. "\n"
			else
					s = s .. "No findings\n\n"
			end

			stdnse.print_debug(1, "vulscan: " .. #vul .. " matches in " .. v.file)
		end

		stdnse.print_debug(1, "vulscan: " .. v_count .. " matches in total")
	end

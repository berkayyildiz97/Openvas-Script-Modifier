###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefox_xsl_parsing_vuln_win.nasl 12629 2018-12-03 15:19:43Z cfischer $
#
# Firefox XSL Parsing Vulnerability (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800379");
  script_version("$Revision: 12629 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-03 16:19:43 +0100 (Mon, 03 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-04-08 08:04:29 +0200 (Wed, 08 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1169");
  script_bugtraq_id(34235);
  script_name("Firefox XSL Parsing Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34471");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/8285");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Mar/1021941.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-12.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_portable_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker cause remote code execution
  through a specially crafted malicious XSL file or can cause application termination at runtime.");

  script_tag(name:"affected", value:"Firefox version 3.0 to 3.0.7 on Windows.");

  script_tag(name:"insight", value:"This flaw is due to improper handling of errors encountered when transforming
  an XML document which can be exploited to cause memory corrpution through a specially crafted XSLT code.");

  script_tag(name:"solution", value:"Upgrade to Firefox version 3.0.8.");

  script_tag(name:"summary", value:"The host is installed with Mozilla Firefox browser and is prone
  to XSL File Parsing Vulnerability.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Win/Ver");
if(!ffVer){
  exit(0);
}

if(version_in_range(version:ffVer, test_version:"3.0", test_version2:"3.0.7")){
  report = report_fixed_ver(installed_version:ffVer, vulnerable_range:"3.0 - 3.0.7");
  security_message(port: 0, data: report);
}

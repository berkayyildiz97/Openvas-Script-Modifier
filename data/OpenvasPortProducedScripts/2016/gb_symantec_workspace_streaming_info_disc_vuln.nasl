###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_workspace_streaming_info_disc_vuln.nasl 12455 2018-11-21 09:17:27Z cfischer $
#
# Symantec Workspace Streaming Information Disclosure Vulnerability
#
# Authors:
# Tushar Khelge <tushar.khelge@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:symantec:workspace_streaming";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808586");
  script_version("$Revision: 12455 $");
  script_cve_id("CVE-2014-1649");
  script_bugtraq_id(67189);
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 10:17:27 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-07-18 17:09:19 +0530 (Mon, 18 Jul 2016)");
  script_name("Symantec Workspace Streaming Information Disclosure Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Symantec
  Symantec Workspace Streaming and is prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to symantec workspace
  streaming server does not properly handle incoming HTTPS XMLRPC requests.");

  script_tag(name:"impact", value:"Successful exploitation allows remote
  attackers to execute arbitrary code on the server and create an unauthorized
  access point on the server.");

  script_tag(name:"affected", value:"Symantec Workspace Streaming before 7.5.0.749.");

  script_tag(name:"solution", value:"Update Symantec Workspace Streaming version 7.5.0.749
  and later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://zerodayinitiative.com/advisories/ZDI-14-127");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_symantec_workspace_streaming_detect.nasl");
  script_mandatory_keys("Symantec/Workspace/Streaming/Agent/Win6432/Installed");
  script_xref(name:"URL", value:"https://support.symantec.com/");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!sepVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:sepVer, test_version:"7.5.0.749"))
{
  report = report_fixed_ver(installed_version:sepVer, fixed_version:"7.5.0.749");
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}

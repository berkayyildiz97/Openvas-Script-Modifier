###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ucs_manager_cisco-sa-20170405-ucs.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco UCS Manager Debug Plug-in Privilege Escalation Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:cisco:unified_computing_system_software";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106734");
  script_cve_id("CVE-2017-6598");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12106 $");

  script_name("Cisco UCS Manager Debug Plug-in Privilege Escalation Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170405-ucs");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the debug plug-in functionality of the Cisco Unified
Computing System (UCS) Manager could allow an authenticated, local attacker to execute arbitrary commands.");

  script_tag(name:"insight", value:"The vulnerability is due to inadequate integrity checks for the debug
plug-in. An attacker could exploit this vulnerability by crafting a debug plug-in and loading it using elevated
privileges.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to run malicious code that would allow
for the execution of arbitrary commands as root.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-10 10:27:18 +0200 (Mon, 10 Apr 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_ucs_manager_detect.nasl");
  script_mandatory_keys("cisco_ucs_manager/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (version == "3.1(1k)A") {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}

exit(0);

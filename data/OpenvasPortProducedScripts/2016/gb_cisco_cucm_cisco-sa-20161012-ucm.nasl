###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_cucm_cisco-sa-20161012-ucm.nasl 14181 2019-03-14 12:59:41Z cfischer $
#
# Cisco Unified Communications Manager iFrame Data Clickjacking Vulnerability
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:cisco:unified_communications_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107061");
  script_cve_id("CVE-2016-6440");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("$Revision: 14181 $");

  script_name("Cisco Unified Communications Manager iFrame Data Clickjacking Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161012-ucm");

  script_tag(name:"impact", value:"An exploit could allow the attacker to perform a clickjacking or phishing attack where the user is
  tricked into clicking on a malicious link. Protection mechanisms should be used to prevent this type of attack.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerability is due to a lack of proper input sanitization of iframe data within the HTTP requests
  sent to the device. An attacker could exploit this vulnerability by sending crafted HTTP packets with malicious iframe data.");
  script_tag(name:"solution", value:"Updates are available. Please see the vendor advisory for more information.");
  script_tag(name:"summary", value:"could allow the attacker to perform a clickjacking or phishing attack where the user is tricked into clicking on a malicious link.");
  script_tag(name:"affected", value:"Cisco Unified Communications Manager 11.0(1.10000.10), 11.5(1.10000.6) and 11.5(0.99838.4) are affected.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2019-03-14 13:59:41 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-10-14 14:48:29 +0100 (Fri, 14 Oct 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_cucm_version.nasl");
  script_mandatory_keys("cisco/cucm/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! vers = get_app_version( cpe:CPE ) ) exit( 0 );

# example for detected version: 11.0.1.10000-10
vers = str_replace( string:vers, find:"-", replace:"." );

if( (vers ==  '11.0.1.10000.10')  || (vers == '11.5.1.10000.6') || (vers == '11.5.0.99838.4'))
{
  report = report_fixed_ver(  installed_version:vers, fixed_version:"See vendor advisory" );
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit( 0 );
}

exit( 99 );

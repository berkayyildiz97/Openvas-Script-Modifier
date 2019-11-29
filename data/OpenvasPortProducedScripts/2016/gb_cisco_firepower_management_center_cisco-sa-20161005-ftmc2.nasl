###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_firepower_management_center_cisco-sa-20161005-ftmc2.nasl 12431 2018-11-20 09:21:00Z asteins $
#
# Cisco Firepower Management Center Console Local File Inclusion Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
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

CPE = "cpe:/a:cisco:firepower_management_center";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106335");
  script_cve_id("CVE-2016-6435");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_version("$Revision: 12431 $");

  script_name("Cisco Firepower Management Center Console Local File Inclusion Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161005-ftmc2");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the web console of Cisco Firepower Management Center
could allow an authenticated, remote attacker to access sensitive information.");

  script_tag(name:"insight", value:"The vulnerability is due to improper validation of parameters that are sent
to the web console of an affected system. The vulnerability could allow an authenticated console user to access
files that are readable by the www user on the server.");

  script_tag(name:"impact", value:"An attacker who has user privileges for the web console could leverage this
vulnerability to read some of the files on the underlying operating system.");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-11-20 10:21:00 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-10-06 11:16:38 +0700 (Thu, 06 Oct 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_firepower_management_center_version.nasl");
  script_mandatory_keys("cisco_firepower_management_center/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( version == '6.0.1' )
{
  report = report_fixed_ver(  installed_version:version, fixed_version: "See advisory" );
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit( 0 );
}

exit( 99 );


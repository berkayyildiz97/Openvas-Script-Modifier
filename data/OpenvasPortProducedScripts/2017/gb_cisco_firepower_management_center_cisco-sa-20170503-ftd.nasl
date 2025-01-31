###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco Firepower Threat Defense and Cisco ASA with FirePOWER Module Denial of Service Vulnerability
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

CPE = "cpe:/a:cisco:firepower_management_center";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106802");
  script_cve_id("CVE-2017-6625");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_version("2019-10-09T06:43:33+0000");

  script_name("Cisco Firepower Threat Defense and Cisco ASA with FirePOWER Module Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170503-ftd");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the access control policy of Cisco Firepower System
Software could allow an authenticated, remote attacker to cause an affected system to stop inspecting and
processing packets, resulting in a denial of service (DoS) condition.");

  script_tag(name:"insight", value:"The vulnerability is due to improper SSL policy handling by the affected
software when packets are passed through the sensing interfaces of an affected system.");

  script_tag(name:"impact", value:"An attacker could exploit this vulnerability by sending crafted packets
through a targeted system.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2019-10-09 06:43:33 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-05-10 21:52:03 +0700 (Wed, 10 May 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_firepower_management_center_version.nasl");
  script_mandatory_keys("cisco_firepower_management_center/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe:CPE))
  exit(0);

affected = make_list(
  '6.0.0',
  '6.0.0',
  '6.0.1',
  '6.0.1',
  '6.1.0',
  '6.1.0',
  '6.1.0.2',
  '6.1.0.2',
  '6.2.0',
  '6.2.0',
  '6.2.1',
  '6.2.1',
  '6.2.2',
  '6.2.2');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    if(!port = get_app_port(cpe: CPE)) port = 0;
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);


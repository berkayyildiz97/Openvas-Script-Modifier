###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco IOS XE Software for Cisco ASR 920 Series Routers Zero Touch Provisioning Denial of Service Vulnerability
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

CPE = "cpe:/o:cisco:ios_xe";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106690");
  script_cve_id("CVE-2017-3859");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("2019-10-09T06:43:33+0000");

  script_name("Cisco IOS XE Software for Cisco ASR 920 Series Routers Zero Touch Provisioning Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170322-ztp");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the DHCP code for the Zero Touch Provisioning feature of
Cisco ASR 920 Series Aggregation Services Routers could allow an unauthenticated, remote attacker to cause an
affected device to reload.");

  script_tag(name:"insight", value:"The vulnerability is due to a format string vulnerability when processing a
crafted DHCP packet for Zero Touch Provisioning. An attacker could exploit this vulnerability by sending a
specially crafted DHCP packet to an affected device.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to cause the device to reload, resulting
in a denial of service (DoS) condition.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2019-10-09 06:43:33 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-03-23 10:27:04 +0700 (Thu, 23 Mar 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_ios_xe_version.nasl");
  script_mandatory_keys("cisco_ios_xe/version", "cisco_ios_xe/model");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

model = get_kb_item("cisco_ios_xe/model");
if (!model || model !~ "^920")
  exit(0);

affected = make_list(
  '3.13.4S',
  '3.13.5S',
  '3.13.5a.S',
  '3.13.6S',
  '3.13.6a.S',
  '3.14.3S',
  '3.14.4S',
  '3.15.2S',
  '3.15.3S',
  '3.15.4S',
  '3.16.0S',
  '3.16.0c.S',
  '3.16.1S',
  '3.16.1a.S',
  '3.16.2S',
  '3.16.2a.S',
  '3.16.2b.S',
  '3.16.3S',
  '3.16.3a.S',
  '3.17.0S',
  '3.17.1S',
  '3.17.1a.S',
  '3.17.2S',
  '3.18.0S',
  '3.18.0SP',
  '3.18.0a.S',
  '3.18.1S',
  '3.18.1SP',
  '3.18.1a.SP',
  '3.18.1b.SP',
  '3.18.1c.SP',
  '3.18.2S',
  '3.18.3v.S');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
    if(!port = get_app_port(cpe: CPE)) port = 0;
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);


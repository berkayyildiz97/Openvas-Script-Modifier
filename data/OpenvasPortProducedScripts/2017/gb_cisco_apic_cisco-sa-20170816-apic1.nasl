###############################################################################
# OpenVAS Vulnerability Test
#
# Cisco Application Policy Infrastructure Controller SSH Privilege Escalation Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = "cpe:/a:cisco:application_policy_infrastructure_controller";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140306");
  script_version("2019-10-09T06:43:33+0000");
  script_tag(name:"last_modification", value:"2019-10-09 06:43:33 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-08-17 09:20:52 +0700 (Thu, 17 Aug 2017)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2017-6767");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cisco Application Policy Infrastructure Controller SSH Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_apic_web_detect.nasl");
  script_mandatory_keys("cisco/application_policy_infrastructure_controller/installed");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"summary", value:"A vulnerability in Cisco Application Policy Infrastructure Controller (APIC)
could allow an authenticated, remote attacker to gain higher privileges than the account is assigned. The attacker
will be granted the privileges of the last user to log in, regardless of whether those privileges are higher or
lower than what should have been granted. The attacker cannot gain root-level privileges.");

  script_tag(name:"insight", value:"The vulnerability is due to a limitation with how Role-Based Access Control
(RBAC) grants privileges to remotely authenticated users when login occurs via SSH directly to the local
management interface of the APIC. An attacker could exploit this vulnerability by authenticating to the targeted
device. The attacker's privilege level will be modified to match that of the last user to log in via SSH.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to gain elevated privileges and perform
CLI commands that should be restricted by the attacker's configured role.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170816-apic1");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

affected = make_list(
  '1.0(1e)',
  '1.0(1h)',
  '1.0(1k)',
  '1.0(1n)',
  '1.0(2j)',
  '1.0(2m)',
  '1.0(3f)',
  '1.0(3i)',
  '1.0(3k)',
  '1.0(3n)',
  '1.0(4h)',
  '1.0(4o)',
  '1.1(0.920a)',
  '1.1(1j)',
  '1.1(3f)',
  '1.2(2)',
  '1.2(3)',
  '1.2.2',
  '1.3(1)',
  '1.3(2)',
  '1.3(2f)',
  '2.0(1)');

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "See advisory.");
    if(!port = get_app_port(cpe: CPE)) port = 0;
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);

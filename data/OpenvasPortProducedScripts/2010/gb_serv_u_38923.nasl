###############################################################################
# OpenVAS Vulnerability Test
#
# Serv-U Multiple Security Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:serv-u:serv-u";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100550");
  script_version("2019-06-24T11:43:03+0000");
  script_tag(name:"last_modification", value:"2019-06-24 11:43:03 +0000 (Mon, 24 Jun 2019)");
  script_tag(name:"creation_date", value:"2010-03-24 17:54:30 +0100 (Wed, 24 Mar 2010)");
  script_bugtraq_id(38923);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Serv-U Multiple Security Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38923");
  script_xref(name:"URL", value:"http://www.serv-u.com/releasenotes/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("FTP");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_solarwinds_serv-u_consolidation.nasl");
  script_mandatory_keys("solarwinds/servu/detected");

  script_tag(name:"solution", value:"The vendor has released an update. Please see the references
  for details.");

  script_tag(name:"summary", value:"Serv-U is prone to multiple security vulnerabilities including security-
  bypass issues and a denial-of-service issue.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to bypass certain security
  restrictions or crash the affected application.");

  script_tag(name:"affected", value:"Versions prior to Serv-U 9.4.0.0 are vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "9.4.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.4.0.0");
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sophos_xg_path_trav_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Sophos XG Firewall Path Traversal Vulnerability
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
# of the License, or (at your option) any later version
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

CPE = 'cpe:/a:sophos:xg';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106903");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-23 10:58:06 +0700 (Fri, 23 Jun 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Sophos XG Firewall Path Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sophos_xg_detect.nasl", "gb_sophos_xg_detect_userportal.nasl");
  script_mandatory_keys("sophos/xg/installed");

  script_tag(name:"summary", value:"Sophos XG Firewall is prone to a path traversal vulnerability where a
low privileged user may download arbitrary files or elevate his privileges.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Crafting a download request and adding a path traversal vector to it, an
authenticated user, can use this function to download files that are outside the normal scope of the download
feature (including sensitive files).

In addition, the function can be called from a low privileged user, a user that is logged on to the User Portal.
A combinations of these two vulnerabilities can be used to compromise the integrity of the server, by allowing a
user to elevate his privileges.");

  script_tag(name:"affected", value:"Sophos XG Firewall before version 16.05.5 MR5");

  script_tag(name:"solution", value:"Update to version 16.05.5 MR5 or later.");

  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/3253");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less(version: version, test_version: "16.05.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "16.05.5");
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}

exit(0);

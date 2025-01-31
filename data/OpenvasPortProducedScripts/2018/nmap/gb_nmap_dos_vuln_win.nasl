# Copyright (C) 2018 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

CPE = "cpe:/a:nmap:nmap";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813825");
  script_version("2019-08-14T08:06:18+0000");
  script_cve_id("CVE-2018-15173");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-08-14 08:06:18 +0000 (Wed, 14 Aug 2019)");
  script_tag(name:"creation_date", value:"2018-08-14 12:02:26 +0530 (Tue, 14 Aug 2018)");

  script_name("Nmap Denial of Service Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with Nmap
  and is prone to denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaw exist due to -sV option usage and
  an improper validation for a crafted TCP-based service via an unknown function
  of the component TCP Connection Handler.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause stack consumption leading to denial of service condition.");

  script_tag(name:"affected", value:"Nmap versions 7.70 and prior on Windows.");

  script_tag(name:"solution", value:"Update to Nmap 7.80 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://code610.blogspot.com/2018/07/crashing-nmap-770.html");
  script_xref(name:"URL", value:"https://seclists.org/nmap-announce/2019/0");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("gb_nmap_detect_win.nasl");
  script_mandatory_keys("Nmap/Win/Ver");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"7.80")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.80", install_path:path);
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}

exit(0);

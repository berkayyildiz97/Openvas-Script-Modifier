# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:zoom:zoom";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815257");
  script_version("2019-07-22T05:46:27+0000");
  script_cve_id("CVE-2019-13449");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-07-22 05:46:27 +0000 (Mon, 22 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-19 15:12:23 +0530 (Fri, 19 Jul 2019)");
  script_name("Zoom Client Denial of Service Vulnerability July19 -MAC OS X");

  script_tag(name:"summary", value:"The host is installed with Zoom Client
  and is prone to a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an improper validation
  of requests to 'launch?action=join&confno=' on port 19421.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause denial of service condition.");

  script_tag(name:"affected", value:"Zoom Client before version 4.4.2 on MAC OS X");

  script_tag(name:"solution", value:"Upgrade to Zoom Client 4.4.2 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://zoom.us/support/download");
  script_xref(name:"URL", value:"https://blog.zoom.us/wordpress/2019/07/08/response-to-video-on-concern/");
  script_xref(name:"URL", value:"https://assets.zoom.us/docs/pdf/Zoom+Response+Video-On+Vulnerability.pdf");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_zoom_client_detect_macosx.nasl");
  script_mandatory_keys("Zoom/Macosx/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
zoomver = infos['version'];
zoompath = infos['location'];

if(version_is_less(version:zoomver, test_version:"4.4.2"))
{
  report = report_fixed_ver(installed_version:zoomver, fixed_version:"4.4.2", install_path:zoompath);
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}
exit(99);

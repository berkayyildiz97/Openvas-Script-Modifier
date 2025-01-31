# Copyright (C) 2019 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114076");
  script_version("2019-04-03T09:59:09+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-04-03 09:59:09 +0000 (Wed, 03 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-02-26 14:56:16 +0100 (Tue, 26 Feb 2019)");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_name("Beward IP Cameras Unauthenticated RTSP Stream Disclosure Vulnerability");
  script_dependencies("gb_beward_ip_cameras_detect_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("beward/ip_camera/detected");

  script_xref(name:"URL", value:"https://www.zeroscience.mk/en/vulnerabilities/ZSL-2019-5509.php");

  script_tag(name:"summary", value:"The remote installation of Beward's IP camera software is prone to
  an unauthenticated and unauthorized live RTSP video stream disclosure vulnerability.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to
  gain information, depending on what the camera is used for.");

  script_tag(name:"insight", value:"Some hosts expose their RTSP video stream to the public by
  allowing unauthenticated users to access the /cgi-bin/view/image page.");

  script_tag(name:"vuldetect", value:"Checks if the host responds with an image.");

  script_tag(name:"affected", value:"At least versions M2.1.6.04C014 and before.");

  script_tag(name:"solution", value:"No known solution is available as of 03rd April, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

CPE = "cpe:/h:beward";

if(!info = get_app_port_from_cpe_prefix(cpe: CPE, service: "www"))
  exit(0);

CPE = info["cpe"];
port = info["port"];

if(!get_app_location(cpe: CPE, port: port)) # nb: Unused but added to have a reference to the Detection-NVT
  exit(0);

url = "/cgi-bin/view/image";

req = http_get_req(port: port, url: url);
res = http_keepalive_send_recv(port: port, data: req);

if("Content-type: image/jpeg" >< res && "Your client does not have permission" >!< res) {
  report = report_vuln_url(port: port, url: url);
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

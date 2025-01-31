##############################################################################
# OpenVAS Vulnerability Test
#
# Google Chrome Security Updates(stable-channel-update_13-2016-04)-Windows
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807546");
  script_version("2019-07-17T08:15:16+0000");
  script_cve_id("CVE-2016-1652", "CVE-2016-1653", "CVE-2016-1651", "CVE-2016-1654",
                "CVE-2016-1655", "CVE-2016-1656", "CVE-2016-1657", "CVE-2016-1658",
                "CVE-2016-1659");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-07-17 08:15:16 +0000 (Wed, 17 Jul 2019)");
  script_tag(name:"creation_date", value:"2016-04-18 16:52:03 +0530 (Mon, 18 Apr 2016)");
  script_name("Google Chrome Security Updates(stable-channel-update_13-2016-04)-Windows");

  script_tag(name:"summary", value:"The host is installed with Google Chrome
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The multiple flaws exist due to

  - A universal XSS in the browser's extension bindings.

  - An out-of-bounds write in Chrome's V8 JavaScript engine.

  - An out-of-bounds memory read issue in Pdfium JPEG2000 decoding.

  - An Uninitialized memory read in browser's media component.

  - An use-after-free in the extensions component.

  - A path restriction bypass in download implementation on Android.

  - An Address bar spoofing vulnerability.

  - The Extensions subsystem incorrectly relies on GetOrigin method calls for
    origin comparisons.

  - Multiple unspecified vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation of this
  vulnerability will allow remote attackers to execute arbitrary code,
  to obtain sensitive information and to cause denial of service or possibly
  have other impact via unknown vectors.");

  script_tag(name:"affected", value:"Google Chrome version
  prior to 50.0.2661.75 on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  50.0.2661.75 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2016/04/stable-channel-update_13.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!chr_ver = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chr_ver, test_version:"50.0.2661.75"))
{
  report = report_fixed_ver(installed_version:chr_ver, fixed_version:"50.0.2661.75");
  if(!port = get_app_port(cpe: CPE)) port = 0;
  security_message(port:port, data:report);
  exit(0);
}

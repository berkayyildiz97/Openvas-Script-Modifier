###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Thunderbird Multiple Vulnerabilities-02 September14 (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804836");
  script_version("2019-06-25T08:25:15+0000");
  script_cve_id("CVE-2014-1565", "CVE-2014-1564", "CVE-2014-1563", "CVE-2014-1553");
  script_bugtraq_id(69521, 69525, 69523, 69524);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-06-25 08:25:15 +0000 (Tue, 25 Jun 2019)");
  script_tag(name:"creation_date", value:"2014-09-05 20:20:31 +0530 (Fri, 05 Sep 2014)");

  script_name("Mozilla Thunderbird Multiple Vulnerabilities-02 September14 (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Thunderbird and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An out-of-bounds read error when creating an audio timeline in Web Audio.

  - An error when decoding GIF images.

  - A use-after-free error during cycle collection when animating SVG content.

  - Some other unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to disclose potentially sensitive information and compromise a user's system.");

  script_tag(name:"affected", value:"Mozilla Thunderbird 31.x before 31.1 on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version
  31.1 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/59236");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-67.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-68.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-69.html");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2014/mfsa2014-70.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Thunderbird/MacOSX/Version");
  script_xref(name:"URL", value:"http://www.mozilla.com/en-US/thunderbird");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!tbVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(tbVer =~ "^31\.")
{
  if(version_is_equal(version:tbVer, test_version:"31.0"))
  {
    if(!port = get_app_port(cpe: CPE)) port = 0;
    security_message(port:port, data:"Thetargethostwasfoundtobevulnerable");
    exit(0);
  }
}

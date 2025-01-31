###############################################################################
# OpenVAS Vulnerability Test
#
# Mozilla Firefox ESR Multiple Vulnerabilities - Aug15 (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806023");
  script_version("2019-07-17T11:14:11+0000");
  script_cve_id("CVE-2015-4473", "CVE-2015-4475", "CVE-2015-4478", "CVE-2015-4479",
                "CVE-2015-4480", "CVE-2015-4482", "CVE-2015-4484", "CVE-2015-4485",
                "CVE-2015-4486", "CVE-2015-4487", "CVE-2015-4488", "CVE-2015-4489",
                "CVE-2015-4492", "CVE-2015-4493");
  script_bugtraq_id(76294, 76297);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-07-17 11:14:11 +0000 (Wed, 17 Jul 2019)");
  script_tag(name:"creation_date", value:"2015-08-19 11:54:33 +0530 (Wed, 19 Aug 2015)");
  script_name("Mozilla Firefox ESR Multiple Vulnerabilities - Aug15 (Mac OS X)");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Firefox ESR and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - The 'mozilla::AudioSink' function in Mozilla Firefox mishandles inconsistent
    sample formats within MP3 audio data.

  - Not imposing certain ECMAScript 6 requirements on JavaScript object
    properties.

  - Multiple integer overflows in libstagefright.

  - Vulnerability in 'mar_read.c' script in the Updater.

  - Vulnerability in 'js::jit::AssemblerX86Shared::lock_addl' function in the
    JavaScript implementation.

  - Heap-based buffer overflow in the 'resize_context_buffers' function in
    libvpx.

  - Vulnerability in decrease_ref_count function in libvpx.

  - Overflow vulnerability in 'nsTSubstring::ReplacePrep' function.

  - Use-after-free vulnerability in the 'StyleAnimationValue' class.

  - Vulnerability in 'nsTArray_Impl' class in Mozilla Firefox.

  - Use-after-free vulnerability in the 'XMLHttpRequest::Open' implementation.

  - Heap-based buffer overflow in the 'stagefright::ESDS::parseESDescriptor'
    function in libstagefright.

  - Multiple unspecified vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow local
  and remote attackers to cause a denial of service or possibly execute arbitrary
  code, gain privileges and some unspecified impacts.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version 38.x before
  38.2 on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version
  38.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-90/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-83/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox-ESR/MacOSX/Version");

  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!ffVer = get_app_version(cpe:CPE)){
   exit(0);
}

if(ffVer =~ "^38\.")
{
  if(version_is_less(version:ffVer, test_version:"38.2"))
  {
    report = 'Installed version: ' + ffVer + '\n' +
             'Fixed version:     ' + "38.2" + '\n';
    if(!port = get_app_port(cpe: CPE)) port = 0;
    security_message(port:port, data:report);
    exit(0);
  }
}

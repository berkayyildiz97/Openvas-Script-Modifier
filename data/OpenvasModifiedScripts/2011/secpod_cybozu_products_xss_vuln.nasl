###############################################################################
# OpenVAS Vulnerability Test
#
# Cybozu Products Images Cross-Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902535");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2011-07-05 13:15:06 +0200 (Tue, 05 Jul 2011)");
  script_cve_id("CVE-2011-1333");
  script_bugtraq_id(48446);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Cybozu Products Images Cross-Site Scripting Vulnerability");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_cybozu_products_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("cybozu_products/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"Cybozu Office 6

  Cybozu Garoon version 2.0.0 through 2.1.3");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of unspecified input related to
  downloading images from the bulletin board, which allows attackers to execute
  arbitrary HTML and script code in a user's browser session in context of an affected site.");

  script_tag(name:"solution", value:"Upgrade to Cybozu Garoon version 2.5.0, Cybozu Office 7 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"This host is running Cybozu Office or Cybozu Garoon and is prone
  to cross site scripting vulnerability.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/45063");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN80877328/index.html");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2011/JVNDB-2011-000045.html");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:80);

if(vers = get_version_from_kb(port:port, app:"CybozuOffice"))
{
  if(vers =~ "^6\.*")
  {
    security_message(port:port);
    exit(0);
  }
}

if(vers = get_version_from_kb(port:port, app:"CybozuGaroon"))
{
  if(version_in_range(version:vers, test_version:"2.0.0", test_version2:"2.1.3")){
    report = report_fixed_ver(installed_version:vers, vulnerable_range:"2.0.0 - 2.1.3");
    security_message(port: port, data: report);
  }
}

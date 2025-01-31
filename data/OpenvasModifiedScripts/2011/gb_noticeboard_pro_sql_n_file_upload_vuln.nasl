##############################################################################
# OpenVAS Vulnerability Test
#
# NoticeBoardPro SQL Injection and Arbitrary File Upload Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802114");
  script_version("2019-12-12T19:26:57+0000");
  script_tag(name:"last_modification", value:"2019-12-12 19:26:57 +0000 (Thu, 12 Dec 2019)");
  script_tag(name:"creation_date", value:"2011-07-07 15:43:33 +0200 (Thu, 07 Jul 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("NoticeBoardPro SQL Injection and Arbitrary File Upload Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/44595/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17296/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"The flaws are due to

  - Input passed via the 'userID' parameter to 'deleteItem3.php' is not
  properly sanitised before being used in SQL queries.

  - An error in 'editItem1.php' script, while validating an uploaded files
  which leads to execution of arbitrary PHP code by uploading a PHP file.");

  script_tag(name:"solution", value:"Upgrade to NoticeBoardPro version 1.1.");

  script_tag(name:"summary", value:"This host is running NoticeBoardPro and is prone to SQL injection
  and arbitrary file upload vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary script code in a user's browser session in the context of an affected
  application and to manipulate SQL queries by injecting arbitrary SQL code.");

  script_tag(name:"affected", value:"NoticeBoardPro version 1.0");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/NoticeBoardPro", "/noticeboardpro", "/", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  res = http_get_cache(item: dir + "/index.php", port:port);

  if("<title>Notice Board</title>" >< res)
  {
    nbVer = eregmatch(pattern:">Version ([0-9.]+)" , string:res);
    if(nbVer[1] != NULL)
    {
      if(version_is_equal(version:nbVer[1], test_version:"1.0")){
        report = report_fixed_ver(installed_version:nbVer[1], vulnerable_range:"Equal to 1.0");
        security_message(port: port, data: report);
        exit(0);
      }
    }
  }
}

exit(99);

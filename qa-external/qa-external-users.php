<?php
require_once(dirname(__FILE__).'/handler.php');

function qa_get_mysql_user_column_type()
{
	return 'VARCHAR(32)';
}


function qa_get_login_links($relative_url_prefix, $redirect_back_to_url)
{
	return QACASHandler::getUrls($relative_url_prefix, $redirect_back_to_url);
}


function qa_get_logged_in_user() {
	return QACASHandler::getUser();
}


function qa_get_user_email($userid)
{
	return QACASHandler::getEmail($userid);
}


function qa_get_userids_from_public($publicusernames)
{
	return QACASHandler::getUserIds($publicusernames);
}


function qa_get_public_from_userids($userids)
{
	return QACASHandler::getUsernames($userids);
}


function qa_get_logged_in_user_html($logged_in_user, $relative_url_prefix)
{
	$publicusername = $logged_in_user['publicusername'];
	$displayname = isset($logged_in_user['display']) ? $logged_in_user['display'] : $publicusername;
	return '<a href="'.qa_path_html('user/'.$publicusername).'" class="qa-user-link">'.htmlspecialchars($displayname).'</a>';
}


function qa_get_users_html($userids, $should_include_link, $relative_url_prefix)
{
	$users = QACASHandler::getUsers($userids);
	$result = array();
	
	foreach($users as $userid => $data) {
		$publicusername = $data['publicusername'];
		$displayname = isset($data['display']) ? $data['display'] : $publicusername;
		
		$result[$userid] = htmlspecialchars($displayname);
		
		if($should_include_link) {
			$result[$userid] = '<a href="'.qa_path_html('user/'.$publicusername).'" class="qa-user-link">'.$result[$userid].'</a>';
		}
	}
	
	return $result;
}


function qa_avatar_html_from_userid($userid, $size, $padding)
{
	return null; // show no avatars by default
}


function qa_user_report_action($userid, $action)
{
}

from lazysre.channels import format_channel_reply, parse_channel_message


def test_parse_generic_channel_message() -> None:
    msg = parse_channel_message("generic", {"text": "检查 swarm", "user_id": "u1"})
    assert msg.text == "检查 swarm"
    assert msg.user_id == "u1"


def test_parse_telegram_message_and_format_reply() -> None:
    msg = parse_channel_message(
        "telegram",
        {"update_id": 1001, "message": {"text": "看一下 k8s", "chat": {"id": 123}, "from": {"id": 456}}},
    )
    assert msg.text == "看一下 k8s"
    assert msg.event_id == "1001"
    reply = format_channel_reply("telegram", "ok", msg)
    assert reply == {"method": "sendMessage", "chat_id": "123", "text": "ok"}


def test_parse_dingtalk_message_and_format_reply() -> None:
    msg = parse_channel_message(
        "dingtalk",
        {"msgId": "m-1", "text": {"content": "排查 nginx"}, "senderStaffId": "staff", "conversationId": "conv"},
    )
    assert msg.text == "排查 nginx"
    assert msg.event_id == "m-1"
    assert format_channel_reply("dingtalk", "done", msg)["text"]["content"] == "done"


def test_parse_feishu_message() -> None:
    msg = parse_channel_message(
        "feishu",
        {
            "header": {"event_id": "evt-1"},
            "event": {
                "sender": {"sender_id": {"open_id": "ou_1"}},
                "message": {"chat_id": "oc_1", "content": '{"text":"检查远程服务器"}'},
            }
        },
    )
    assert msg.text == "检查远程服务器"
    assert msg.user_id == "ou_1"
    assert msg.event_id == "evt-1"


def test_parse_onebot_message() -> None:
    msg = parse_channel_message("onebot", {"raw_message": "看看 docker", "user_id": 1, "group_id": 2, "message_id": 99})
    assert msg.text == "看看 docker"
    assert msg.chat_id == "2"
    assert msg.event_id == "99"

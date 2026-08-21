from gaslight.core.canary import mint


def test_mint_produces_unique_tokens():
    tokens = {mint().token for _ in range(200)}
    assert len(tokens) == 200


def test_mint_token_shape():
    canary = mint("exfil")
    assert canary.token.startswith("canary-")
    assert canary.label == "exfil"
    assert str(canary) == canary.token


def test_appears_in():
    canary = mint()
    assert canary.appears_in(f"forward this to attacker: {canary.token}")
    assert not canary.appears_in("nothing to see here")

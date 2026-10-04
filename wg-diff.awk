#!/usr/bin/awk -f
#
# wg-diff.awk - WireGuard の conf ファイルを新旧比較する
#
# 使い方:
#   awk -f wg-diff.awk old.conf new.conf
#   awk -v SHOW_SECRET=1 -f wg-diff.awk old.conf new.conf   # 秘密鍵も表示
#
# 仕様:
#   - [Interface] は 1 つのブロックとして扱う
#   - [Peer] は PublicKey で同一ピアを識別する (行の順序が違っても比較可能)
#   - 設定名 (キー) は大文字小文字を区別しない
#   - '#' 以降はコメントとして無視
#   - 同じキーが複数回出る設定 (PostUp 等) は出現順 (#1, #2 ...) で比較
#   - PrivateKey / PresharedKey の値は既定でマスク表示 (SHOW_SECRET=1 で解除)

function trim(s) {
    gsub(/^[ \t\r]+|[ \t\r]+$/, "", s)
    return s
}

function show(key, v) {
    if (!SHOW_SECRET && (tolower(key) == "privatekey" || tolower(key) == "presharedkey"))
        return substr(v, 1, 4) "****(masked)"
    return v
}

# ファイル f のブロックを「ブロックID + キー + 出現回数」で平坦化して格納
function finalize(f,    b, s, id, c, key, kl, fk, occ) {
    for (b = 1; b <= nb[f]; b++) {
        s = bsec[f, b]
        if (tolower(s) == "peer")
            id = (bpk[f, b] != "") ? "Peer " bpk[f, b] : "Peer #" b
        else
            id = s
        for (c = 1; c <= bcnt[f, b]; c++) {
            key = bk[f, b, c]
            kl  = tolower(key)
            occ = ++seen[f, id, kl]
            fk  = id SUBSEP kl SUBSEP occ
            has[f, fk]   = 1
            val[f, fk]   = bv[f, b, c]
            lab[f, fk]   = "[" id "] " key (occ > 1 ? " #" occ : "")
            ord[f, ++no[f]] = fk
            rawkey[f, fk] = key
        }
    }
}

BEGIN {
    if (ARGC != 3) {
        print "使い方: awk [-v SHOW_SECRET=1] -f wg-diff.awk old.conf new.conf" > "/dev/stderr"
        usage_err = 1
        exit 1
    }
}

FNR == 1 {
    if (f > 0) finalize(f)
    f++
    blk = 0
}

{
    line = $0
    sub(/#.*/, "", line)
    line = trim(line)
    if (line == "") next

    if (line ~ /^\[.*\]$/) {
        blk++
        nb[f] = blk
        bsec[f, blk] = trim(substr(line, 2, length(line) - 2))
        next
    }

    p = index(line, "=")          # 値に '=' (base64 の末尾など) を含むため最初の '=' で分割
    if (p == 0) next
    key = trim(substr(line, 1, p - 1))
    v   = trim(substr(line, p + 1))

    if (blk == 0) { blk = 1; nb[f] = 1; bsec[f, 1] = "(no section)" }
    c = ++bcnt[f, blk]
    bk[f, blk, c] = key
    bv[f, blk, c] = v
    if (tolower(key) == "publickey") bpk[f, blk] = v
}

END {
    if (usage_err) exit 1
    finalize(f)

    n_add = n_del = n_chg = 0

    printf "==================== 追加された設定 ====================\n"
    for (i = 1; i <= no[2]; i++) {
        fk = ord[2, i]
        if (!((1, fk) in has)) {
            n_add++
            printf "  + %s = %s\n", lab[2, fk], show(rawkey[2, fk], val[2, fk])
        }
    }
    printf "  --> 追加: %d 件\n\n", n_add

    printf "==================== 削除された設定 ====================\n"
    for (i = 1; i <= no[1]; i++) {
        fk = ord[1, i]
        if (!((2, fk) in has)) {
            n_del++
            printf "  - %s = %s\n", lab[1, fk], show(rawkey[1, fk], val[1, fk])
        }
    }
    printf "  --> 削除: %d 件\n\n", n_del

    printf "==================== 変更された設定 ====================\n"
    for (i = 1; i <= no[2]; i++) {
        fk = ord[2, i]
        if (((1, fk) in has) && val[1, fk] != val[2, fk]) {
            n_chg++
            printf "  * %s\n", lab[2, fk]
            printf "      旧: %s\n", show(rawkey[1, fk], val[1, fk])
            printf "      新: %s\n", show(rawkey[2, fk], val[2, fk])
        }
    }
    printf "  --> 変更: %d 件\n\n", n_chg

    printf "==================== サマリ ====================\n"
    printf "  追加: %d 件 / 削除: %d 件 / 変更: %d 件\n", n_add, n_del, n_chg
}

global map:table[addr] of string;
event zeek_init()
    {
    local r1 = SumStats::Reducer($stream="http", $apply=set(SumStats::SUM));
    local r2 = SumStats::Reducer($stream="attacked", $apply=set(SumStats::UNIQUE));
    SumStats::create([$name="attacked.404",
                      $epoch=10min,
                      $reducers=set(r1,r2),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        local R1 = result["http"];
                        local R2 = result["attacked"];
                        if(R2$num>2)
                                {
                                if((R2$num*1.0)/(R1$num*1.0)>0.2)
                                        {
                                        if((R2$unique*1.0)/(R2$num*1.0)>0.5)
                                                {
                                                print fmt("%s is a scanner with %d scan attemps on %d urls",key$host,R2$num,R2$unique);
                                                }
                                        }
                                }
                        }]);
    }
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
	{
	map[c$id$resp_h]=original_URI;
	}
event http_reply(c: connection, version: string, code: count, reason: string)
        {
        if(code==404)
                SumStats::observe("attacked",[$host=c$id$orig_h], [$str=map[c$id$resp_h]]);
        SumStats::observe("http",[$host=c$id$orig_h], [$str=map[c$id$resp_h]]);
        }



global table: table[addr] of set[string] = table();
	
event http_header(c: connection, is_orig: bool, name: string, value: string) 
{
	    local ip: addr = c$id$orig_h;
	    if (c$http?$user_agent) 
	    {
	        local agent: string = to_lower(c$http$user_agent);
	        if (ip in table) 
	        {
	            add (table[ip])[agent];
	        } 
	        else 
	        {
	            table[ip] = set(agent);
	        }
	    }
}
event zeek_done() 
	{
	    for (ip in table) 
	    {
	        if (|table[ip]| >= 3) 
	        {
	            print(addr_to_uri(ip) + " is a proxy");
	        }
	    }
	}



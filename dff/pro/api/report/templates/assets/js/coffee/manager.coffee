namespace "fragments"

  Manager:
    class Manager
      constructor: ->
        @fragments = new Array()    

      create: (fragment) ->
        if fragment.widget
          id = Math.floor((Math.random()*1000)+1)
          switch fragment.widget
            when "text"
              frag = new textFragment(fragment, id)
            when "table"
              frag = new tableFragment(fragment, id)
            when "detail_table"
              frag = new detailTableFragment(fragment, id)
            when "node_list"
              frag = new nodeListFragment(fragment, id)
            when "node"
              frag = new node(fragment, id)
            when "tab"
              frag = new tabFragment(fragment, id)
            when "chat"
              console.log("Coucou ?")
              frag = new chatFragment(fragment, id)
            else return no
          @fragments.push frag
          return frag
        else
          return no

      renderAll: (rootDom) ->
        for frag in @fragments
          frag.render rootDom

      clearAll: () ->
        for f in @fragments
          f.clear()
        @fragments = new Array()
                
  tableFragment = fragments.TableFragment
  tabFragment = fragments.Tab
  detailTableFragment = fragments.DetailTableFragment
  nodeListFragment = fragments.NodeListFragment
  textFragment = fragments.TextFragment
  node = fragments.Node
  chatFragment = fragments.ChatFragment



      

            

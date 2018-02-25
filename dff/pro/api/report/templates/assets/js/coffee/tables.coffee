namespace "fragments"
  NodeListFragment:
    class NodeListFragment extends fragments.FObject
      constructor: (@json, @id) ->
        super @json, @id
        @view = null
        @container = $('<div>').addClass('container')
        @createView(@json.view)

      setTitle: () ->
        return

      createView: (viewid) ->
        if @view then @view.clear()
        @createHeader()
        id = Math.floor((Math.random()*1000)+1)
        if viewid is 0
          v = new fragments.NodeTableFragment(@json, id)
        else
          v = new fragments.NodeGalleryFragment(@json, id)
        if @view
          delete @view
          @view = v
          @view.render @container
        else
          @view = v
        
      render: (rootDom) =>
        super
        @html.append(@container)
        @view.render @container

      createHeader: () ->
        gid = Math.floor((Math.random()*1000)+1)
        tid = Math.floor((Math.random()*1000)+1) 
        header = $('<div>').addClass('container')
        btntoolbar = $('<div>').addClass('btn-toolbar')
        btngroup = $('<div>').addClass('btn-group')
        galleryview = $('<button>').addClass('btn')
          .append($('<i>').addClass('icon-picture'))
          .attr('id', gid.toString())
        tableview = $('<button>').addClass('btn')
          .append($('<i>').addClass('icon-th-list'))
          .attr('id', tid.toString())
        btngroup.append galleryview
        btngroup.append tableview
        btntoolbar.append btngroup
        header.append btntoolbar
        @container.append header

        $('button#'+ gid.toString()).live 'click',
          (event) =>
            event.preventDefault()
            event.stopImmediatePropagation()
            @createView(1)

        $('button#'+tid.toString()).live 'click',
          (event) =>
            event.preventDefault()
            event.stopImmediatePropagation()
            @createView(0)

  NodeTableFragment:
    class NodeTableFragment extends fragments.FObject
      constructor: (@json, @id) ->
        super @json, @id
        @fmanager = new fragments.Manager()
        @container = $('<div>').addClass('container')
        @table = null
        @createTable()
        @setup()
        @connect()

      render: (rootDom) =>
        super
        @html.append(@container)

        dth = $('<th>').attr('width', '1%')      
        $('table.table#node_table_' + @id + ' thead tr').each (id, tr) =>
          $(tr).append(dth)
    
        $('table.table#node_table_' + @id).dataTable(@settings)

      createTable: () ->
        root = $('<div>')
          .addClass("dataTables_wrapper form-inline")
          .attr('role', 'grid')

        row = $('<div>').addClass "row-fluid"
        table = $('<table>')
          .addClass("table table-striped table-bordered dataTable")
          .attr('id', 'node_table_' + @id)
          .attr('width', '100%')

        head = $('<thead>')
        htr = $('<tr>').attr('role', 'row')
        for th in @json.thead
          t = $('<th>')
            .addClass('sorting')
            .attr('role', 'columnheader')
            .attr('tabindex', '0')
            .attr('aria-controls', 'node_table_' + @id)
            .append(th)
          htr.append(t)
        head.append(htr)
        table.append(head)
        row.append(table)
        root.append(row)
        @container.append(root)

      setup: () =>
        @settings = 
          "aaData": @json.data
          "sDom": "<'row-fluid'<'span6'l><'span6'f>r>t<'row-fluid'<'span6'i><'span6'p>>"
          "sPaginationType": "bootstrap"
          "fnRowCallback": (nRow, aData, iDisplayIndex, iDisplayIndexFull ) ->
            if not $(nRow).find('td.detail_img')[0]
              dtd = $('<td>').append('<img src="assets/img/details_open.png">')
              dtd.addClass('center')
              dtd.addClass('detail_img')
              $(nRow).addClass('main')
              $(nRow).append(dtd)
        head = []
        for th in @json.thead
          t = {"mData": th}
          head.push(t)

        add =
          "aoColumns": head
          "aoColumnDefs":[
            "aTargets": [0]
            "mRender": ( data, type, full) ->
              if (full.file)
                if full.thumb
                  return '<span><img src="' + full.thumb + '" class="thumb"><a href="' + full.file + '"> ' + data + '</a></span>'
                else
                  return '<a href="' + full.file + '"> ' + data + '</a>'
              return data
          ]

        for id, value of add
          @settings[id] = value

      connect: () =>
        $('#node_table_' + @id + ' tbody tr.main').live 'mouseover',
          (event) =>
            $(event.currentTarget).addClass('info')
        $('#node_table_' + @id + ' tbody tr.main').live 'mouseout',
          (event) =>
            $(event.currentTarget).removeClass('info')
      
        $('#node_table_' + @id + ' tbody td.detail_img').live 'click', (event) =>
          event.preventDefault()
          event.stopImmediatePropagation()
          tr = $(event.currentTarget).parent()
          table = $('table#node_table_'+ @id).dataTable()
          data = table.fnGetData(tr[0])
          if data
            if tr.hasClass('open')
              fragment = tr.next().find($('.fragment'))
              fid = fragment.attr('id')
              tr.next().remove()
              @fmanager.fragments.splice(fid, 1)
              tr.removeClass('open success')
            else
              tr.addClass('success')
              fragment = @fmanager.create(data)
              colspan = table.fnSettings()['aoColumns'].length#.toString()
              colspan = colspan + 1
              tr.addClass('open')
              dtr = $('<tr>')
              dtd = $('<td>').attr('colspan', colspan.toString())
              dtr.append(dtd)
              tr.after(dtr)
              fragment.render(dtd)

  NodeGalleryFragment:
    class NodeGalleryFragment extends fragments.FObject
      constructor: (@json, @id) ->
        super @json, @id
        @container = $('<div>').addClass('container')
        @setItemSelection()
        @max_visible_pages = 6
        @visible_items = 99
        @current_page = 0
        @refresh()
    
      configurePagination: () ->
        @pages = parseInt((@json.data.length / @visible_items))
        @pages = @pages + 1 if @json.data.length % @visible_items > 0
        @pages = @pages - 1
        @pages = 0 if @pages < 0


      setItemSelection:() ->
        @selection = $('<select>')
          .append($('<option>').append(100))
          .append($('<option>').append(200))
          .append($('<option>').append(500))
        @selection.addClass('itemselection')
        @selection.attr('id', @id)
        @html.append(@selection)

        $('select#'+@id+'.itemselection').live 'change',
          (event) =>
            @visible_items =  event.currentTarget.value - 1
            @refresh()

        # $('select#tr.main').live 'mouseover',
        #   (event) =>
        #     $(event.currentTarget).addClass('info')  

      pagination: () ->
        $('div.row-fluid#pagination').remove()
        paginate = $('<div>').addClass("row-fluid").attr("id", "pagination")
        div_pages = $('<div>').addClass("pagination pagination-centered")
        ul = $('<ul>').attr("id", "pagination")
        start = @current_page - (@current_page % @max_visible_pages)
        end = start + @max_visible_pages
        stop = if end > @pages then @pages else end
        @previous ul
        for num in [start..stop]
          link = $('<a>').attr('href', '#').append(num + 1)
          link.bind 'click' , (event) =>
            @current_page = parseInt($(event.target).text()) - 1
            @refresh()
          if num is @current_page    
            ul.append($('<li>').addClass('active').append(link))
          else
            ul.append($('<li>').append(link))

        @next(ul)
     
        div_pages.append(ul)
        paginate.append(div_pages)
        @container.append(paginate)

      next: (ul) ->
        li = $('<li>')
        a = $('<a>').attr("href", "#").append(">>")
        if @current_page is @pages
          li.addClass('disabled')
        else
          a.bind 'click' , (event) =>
            @current_page = @current_page + 1
            @refresh()
        ul.append(li.append(a))

      previous: (ul) ->
        li = $('<li>')
        a = $('<a>').attr("href", "#").append("<<")
        if @current_page is 0
          li.addClass('disabled')
        else
          a.bind 'click' , (event) =>
            @current_page = @current_page - 1
            @refresh()
        ul.append(li.append(a))

      createGallery: () ->
        $('div#myGallery').remove()
        data = @json.data
        start = @current_page * @visible_items
        start = if @current_page > 0 then start + 1 else start
        end = start + @visible_items
        stop = if end > data.length then data.length else end
        sdata = data[start..stop]
        root = $('<div>').attr('id', 'myGallery')
        for img, i in sdata
          link = $('<a>').attr('href', img.file).addClass('img').attr('title', img.name)
              .append $('<img>').attr('src', img.thumb).attr('id', i+start)
          caption = $('<div>').addClass('caption').attr('id',i+start).append(img.name)
          link.append(caption)
          root.append(link)
        @container.append(root)

      refresh: () ->
        @configurePagination()
        @createGallery().find('#myGallery').justifiedGallery(lastRow : 'justify', margins : 2)
          .on 'jg.complete',->
            $(this).find('a').colorbox()
        .find('.img').on 'click', (event)=>
            $('#cboxMiddleRight').empty()
            console.log event.target.id
            for attr, values of @json.data[event.target.id].row_details.data
             for attr2, value of values
                $('#cboxMiddleRight').append('<tr><td>'+attr2+'</td><td>'+value+'</td></tr>')
        @pagination()

      render: (rootDom) =>
        super
        @html.append(@container)

###### Detail Table ########

  DetailTableFragment:
    class DetailTableFragment extends fragments.FObject
      constructor: (@json, @id) ->
        super @json, @id
#        console.log("coucou test")
        @fmanager = new fragments.Manager()
        @table = null
        @createTable()
        @setup()
        @connect()

      render: (rootDom) =>
        super
        dth = $('<th>')   
        $('table.table#dtable_' + @id + ' thead tr').each (id, tr) =>
          $(tr).prepend(dth)
        $('table.table#dtable_' + @id).dataTable(@settings)

      createTable: () ->
        root = $('<div>').addClass("container")
          .addClass("dataTables_wrapper form-inline")
          .attr('role', 'grid')

        row = $('<div>').addClass "row-fluid"
        table = $('<table>')
          .addClass("table table-striped table-bordered dataTable")
          .attr('id', 'dtable_' + @id)

        head = $('<thead>')
        htr = $('<tr>').attr('role', 'row')
        for th in @json.thead
          t = $('<th>')
            .addClass('sorting')
            .attr('width', '50%')
            .attr('role', 'columnheader')
            .attr('tabindex', '0')
            .attr('aria-controls', 'dtable_' + @id)
            .append(th)
          htr.append(t)

        head.append(htr)
        table.append(head)
        root.append(table)
        root.append(row)
        @html.append(root)

      setup: () =>
        @settings = 
          "aaData": @json.data
          "sDom": "<'row-fluid'<'span6'l><'span6'f>r>t<'row-fluid'<'span6'i><'span6'p>>"
          "sPaginationType": "bootstrap"
          "fnRowCallback": (nRow, aData, iDisplayIndex, iDisplayIndexFull ) ->
            if not $(nRow).find('td.detail_img')[0]
              dtd = $('<td>').append('<img src="assets/img/details_open.png">')
              dtd.addClass('center')
              dtd.addClass('detail_img')
              $(nRow).addClass('main')
              $(nRow).prepend(dtd)
        head = []
        for th in @json.thead
          t = {"mData": th}
          head.push(t)
        add =
          "aoColumns": head
          "aoColumnDefs":[
            "bSortable" :true
            "aTargets": [0]
            "mRender": ( data, type, full) ->
              if full.thumb
                return '<span><img src="' + full.thumb + '" class="thumb"> ' + data + '</span>'
              # if (full.file)
              #   return '<a href="' + full.file + '">' + data + '</a>'
              return data
          ]
        for id, value of add
          @settings[id] = value
    
      connect: () =>
        $('#dtable_' + @id + ' tbody tr.main').live 'mouseover',
          (event) =>
            $(event.currentTarget).addClass('info')
        $('#dtable_' + @id + ' tbody tr.main').live 'mouseout',
          (event) =>
            $(event.currentTarget).removeClass('info')

        $('#dtable_' + @id + ' tbody tr.main').live 'click', (event) =>
          event.preventDefault()
          event.stopImmediatePropagation()
          tr = event.currentTarget
          table = $('table#dtable_'+ @id).dataTable()
          data = table.fnGetData(tr)
          if data['row_details']
            if $(tr).hasClass('open')
              fragment = $(tr).next().find($('.fragment'))
              fid = fragment.attr('id')
              $(tr).next().remove()
              @fmanager.fragments.splice(fid, 1)
              $(tr).removeClass('open success')
              dtd = $(tr).find($('.detail_img'))
              dtd.empty()
              dtd.append('<img src="assets/img/details_open.png">')
            else
              $(tr).addClass('success')
              $(tr).addClass('open')
              dtd = $(tr).find($('.detail_img'))
              dtd.empty()
              dtd.append('<img src="assets/img/details_close.png">')
              fragment = @fmanager.create(data['row_details'])
              colspan = table.fnSettings()['aoColumns'].length
              colspan = colspan + 1
              dtr = $('<tr>')
              dtd = $('<td>').attr('colspan', colspan.toString())
              dtr.append(dtd)
              $(tr).after(dtr)  
              fragment.render(dtd)


  TableFragment:
    class TableFragment extends fragments.FObject
      constructor: (@json, @id) ->
        super @json, @id
        @table = null
        @createTable()
        @setup()

      render: (rootDom) =>
        super
        $('table.table#table_' + @id).DataTable(@settings)

      createTable: () ->
        root = $('<div>')
          .addClass("dataTables_wrapper form-inline")
          .attr('role', 'grid')

        row = $('<div>').addClass "row-fluid"
        table = $('<table>')
          .addClass("table table-striped table-bordered dataTable")
          .attr('id', 'table_' + @id)
          .attr('width', '100%')

        head = $('<thead>')
        htr = $('<tr>').attr('role', 'row')
        for th in @json.thead
          t = $('<th>')
            .addClass('sorting')
            .attr('role', 'columnheader')
            .attr('tabindex', '0')
            .attr('aria-controls', 'table_' + @id)
            .append(th)
          htr.append(t)
        head.append(htr)
        table.append(head)
        row.append(table)
        root.append(row)
        @html.append(root)

      setup: () =>
        @settings = 
          "aaData": @json.data
          "aoColumns" : @json.thead
          "bPaginate": false
          'bFilter': false
          "sDom": 't'#"<'row-fluid'<'span6'l><'span6'f>r>t<'row-fluid'<'span6'i><'span6'p>>"
#          "sPaginationType": "bootstrap"
          # "fnRowCallback": (nRow, aData, iDisplayIndex, iDisplayIndexFull ) ->
          #   $(nRow).addClass('main')

  ChatFragment:
    class ChatFragment extends fragments.FObject
      constructor: (@json, @id) ->
        super @json, @id
#        @table = null
        @createChats()
#        @setup()

      render: (rootDom) =>
        super
#        $('table.table#table_' + @id).DataTable(@settings)

      createChats: () ->
#        console.log("create Chats")
        for chat in @json.data
          date = $('<h4>').append(chat.date)
          @html.append(date)
          chattable = $('<table>')
            .addClass("table")
            .addClass("table-condensed")
            .addClass("table-chat")
          chatbody = $('<tbody>')
#          console.log chat.date
          for message in chat.messages
            tr = $('<tr>')#.addClass('main')
            date = $('<td>').addClass('date')
            date.append(message[0])
            tr.append(date)
            user = $('<td>').addClass('username')
            user.append(message[1])
            tr.append(user)
            m = $('<td>').addClass('message')
            m.append(message[2])
            tr.append(m)
            chatbody.append(tr)
          chattable.append(chatbody)
          @html.append(chattable)

